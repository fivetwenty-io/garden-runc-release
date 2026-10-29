//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// CredHub interpolation. The CF launcher resolves CredHub references in
// VCAP_SERVICES before the app starts (buildpackapplifecycle credhub, and
// credhub-cli InterpolateString); vm-launch replaces the launcher, so it
// makes the same call itself, in the container, with the instance identity.
const (
	credhubSkipEnv      = "CREDHUB_SKIP_INTERPOLATION"
	instanceCertEnv     = "CF_INSTANCE_CERT"
	instanceKeyEnv      = "CF_INSTANCE_KEY"
	systemCertPathEnv   = "CF_SYSTEM_CERT_PATH"
	credhubRefMarker    = `"credhub-ref"`
	credhubInterpolate  = "/api/v1/interpolate"
	credhubCAFileSuffix = ".crt"

	// The launcher's flag names and defaults (buildpackapplifecycle
	// credhub_flags).
	credhubAttemptsFlag    = "credhubConnectAttempts"
	credhubDelayFlag       = "credhubRetryDelay"
	credhubAttemptsDefault = 3
	credhubDelayDefault    = time.Second

	// credhub-cli's client timeout and dial timeout.
	credhubAttemptTimeout = 45 * time.Second
	credhubDialTimeout    = 30 * time.Second
)

// credhubRetry is how often, and how far apart, vm-launch tries CredHub.
type credhubRetry struct {
	attempts int
	delay    time.Duration
}

var defaultCredhubRetry = credhubRetry{attempts: credhubAttemptsDefault, delay: credhubDelayDefault}

// credhubRetryFromArgs parses the launcher's CredHub flags from args, the
// launcher's arguments after APP-DIR and START-COMMAND, as the launcher
// parses them: parsing stops at the first argument that is not a flag, such
// as METADATA, so the defaults apply unless the flags come first. An unknown
// flag, a value that does not parse, fewer than one attempt, and a negative
// delay are errors. The error never wraps the flag package's own, so a -h
// in these arguments is a bad argument and not a request for vm-launch's
// usage.
func credhubRetryFromArgs(args []string) (credhubRetry, error) {
	fs := flag.NewFlagSet("launcher", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	attempts := fs.Int(credhubAttemptsFlag, credhubAttemptsDefault, "number of times to try CredHub")
	delay := fs.Duration(credhubDelayFlag, credhubDelayDefault, "delay between CredHub attempts")
	if err := fs.Parse(args); err != nil {
		return credhubRetry{}, fmt.Errorf("parsing the launcher's CredHub flags: %v", err)
	}
	if *attempts < 1 {
		return credhubRetry{}, fmt.Errorf("parsing the launcher's CredHub flags: -%s must be at least 1, got %d", credhubAttemptsFlag, *attempts)
	}
	if *delay < 0 {
		return credhubRetry{}, fmt.Errorf("parsing the launcher's CredHub flags: -%s must not be negative, got %v", credhubDelayFlag, *delay)
	}
	return credhubRetry{attempts: *attempts, delay: *delay}, nil
}

// credhubClientOptions are the transport settings of the CredHub client.
// Specs shorten the timeout.
type credhubClientOptions struct {
	// timeout bounds one attempt, from the dial to the end of the body.
	timeout time.Duration
	// proxy picks the proxy for a request, as http.Transport.Proxy does.
	proxy func(*http.Request) (*url.URL, error)
}

var defaultCredhubClient = credhubClientOptions{
	timeout: credhubAttemptTimeout,
	proxy:   http.ProxyFromEnvironment,
}

// platformOptions is the launcher's VCAP_PLATFORM_OPTIONS
// (buildpackapplifecycle platformoptions).
type platformOptions struct {
	CredhubURI string `json:"credhub-uri"`
}

// resolveCredhubRefs resolves the CredHub references in VCAP_SERVICES and
// returns the resolved value, with resolved true, when vm-launch must
// replace VCAP_SERVICES with it. It decides whether to run as the launcher
// does:
//
//   - VCAP_PLATFORM_OPTIONS that is set, not empty, and not valid JSON is an
//     error, whether or not a binding holds a reference.
//   - CREDHUB_SKIP_INTERPOLATION set to anything but the empty string, or a
//     VCAP_SERVICES without "credhub-ref", skips the step.
//   - VCAP_PLATFORM_OPTIONS without a credhub-uri skips the step with one
//     line that says the references stay unresolved.
//
// It then makes one mTLS POST of VCAP_SERVICES to CredHub's interpolate
// endpoint per attempt, presenting the instance identity, and trusts only the
// CA files ending in .crt under CF_SYSTEM_CERT_PATH. Each failed attempt
// logs one line with its number, the CredHub host, and a fixed reason, and
// the step waits retry.delay before the next one. retry.attempts is at least
// 1, as credhubRetryFromArgs makes it. A SIGTERM or SIGINT on sigs stops the
// step with a *signalledError, including one that arrives while the last
// attempt fails. No log line or error ever holds the request, the response,
// or text from either.
func resolveCredhubRefs(lookup func(string) (string, bool), retry credhubRetry, opts credhubClientOptions, sigs <-chan os.Signal, logger *log.Logger) (services string, resolved bool, err error) {
	get := func(name string) string {
		v, _ := lookup(name)
		return v
	}

	var options platformOptions
	if raw := get(platformOptionsEnv); raw != "" {
		if err := json.Unmarshal([]byte(raw), &options); err != nil {
			return "", false, fmt.Errorf("%s is not valid JSON platform options", platformOptionsEnv)
		}
	}
	if get(credhubSkipEnv) != "" {
		return "", false, nil
	}
	services = get(vcapServicesEnv)
	if !strings.Contains(services, credhubRefMarker) {
		return "", false, nil
	}
	if options.CredhubURI == "" {
		logger.Printf("a service binding holds a CredHub reference, and %s names no credhub-uri to resolve it; the guest gets the reference unresolved", platformOptionsEnv)
		return "", false, nil
	}

	endpoint, err := credhubEndpoint(options.CredhubURI)
	if err != nil {
		return "", false, err
	}
	body, err := credhubRequestBody(services)
	if err != nil {
		return "", false, err
	}
	client, err := newCredhubClient(get, opts)
	if err != nil {
		return "", false, err
	}
	defer client.CloseIdleConnections()

	for attempt := 1; ; attempt++ {
		out, reason, err := credhubAttempt(client, endpoint, body, sigs)
		if err != nil {
			return "", false, err
		}
		if reason == "" {
			return out, true, nil
		}
		logger.Printf("resolving CredHub references: attempt %d of %d to %s failed: %s", attempt, retry.attempts, endpoint.Host, reason)
		if attempt >= retry.attempts {
			// A signal that arrived while the last attempt failed still
			// decides the exit status.
			select {
			case sig := <-sigs:
				return "", false, credhubSignalled(sig)
			default:
			}
			return "", false, fmt.Errorf("resolving CredHub references at %s failed after %d attempts", endpoint.Host, retry.attempts)
		}
		timer := time.NewTimer(retry.delay)
		select {
		case sig := <-sigs:
			timer.Stop()
			return "", false, credhubSignalled(sig)
		case <-timer.C:
		}
	}
}

// credhubSignalled is the error for a signal that stopped the step.
func credhubSignalled(sig os.Signal) error {
	return &signalledError{Sig: syscall.Signal(signalNumber(sig)), during: "resolving CredHub references"}
}

// credhubEndpoint returns the interpolate URL for credhubURI, which must be
// an https URL with a host. As in credhub-cli, the endpoint path replaces
// any path in credhubURI and the query is dropped.
func credhubEndpoint(credhubURI string) (*url.URL, error) {
	u, err := url.Parse(credhubURI)
	if err != nil {
		return nil, fmt.Errorf("the credhub-uri in %s is not a valid URL", platformOptionsEnv)
	}
	if u.Scheme != "https" || u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("the credhub-uri in %s must be an https URL with a host", platformOptionsEnv)
	}
	if u.User != nil {
		return nil, fmt.Errorf("the credhub-uri in %s must not hold user information", platformOptionsEnv)
	}
	endpoint := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: credhubInterpolate}
	return endpoint, nil
}

// credhubRequestBody returns the request body for VCAP_SERVICES services as
// credhub-cli builds it: decoded into a map and encoded again.
func credhubRequestBody(services string) ([]byte, error) {
	request := map[string]interface{}{}
	if err := json.Unmarshal([]byte(services), &request); err != nil {
		return nil, errors.New("VCAP_SERVICES is not valid JSON, so its CredHub references cannot be resolved")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, errors.New("encoding VCAP_SERVICES for CredHub failed")
	}
	return body, nil
}

// newCredhubClient returns an HTTPS client that presents the instance
// identity named by CF_INSTANCE_CERT and CF_INSTANCE_KEY, trusts only the
// .crt files directly under CF_SYSTEM_CERT_PATH, needs TLS 1.2 or later, and
// never follows a redirect. Its transport is an *http.Transport.
func newCredhubClient(get func(string) string, opts credhubClientOptions) (*http.Client, error) {
	certPath, keyPath, caDir := get(instanceCertEnv), get(instanceKeyEnv), get(systemCertPathEnv)
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("a service binding holds a CredHub reference, and %s or %s is not set", instanceCertEnv, instanceKeyEnv)
	}
	if caDir == "" {
		return nil, fmt.Errorf("a service binding holds a CredHub reference, and %s is not set", systemCertPathEnv)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading the instance certificate %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading the instance key %s: %w", keyPath, err)
	}
	identity, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("loading the instance identity from %s and %s: %w", certPath, keyPath, err)
	}
	pool, err := credhubCAPool(caDir)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: credhubDialTimeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:       opts.proxy,
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{identity},
			RootCAs:      pool,
			MinVersion:   tls.VersionTLS12,
		},
		TLSHandshakeTimeout: opts.timeout,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   opts.timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// credhubCAPool returns a pool of the certificates in the files ending in
// .crt directly under dir. A file that holds no PEM certificate is an error,
// as in credhub-cli, and so is a directory without one.
//
// The pool starts empty. credhub-cli, and so the launcher, starts from the
// system pool and adds these files; vm-launch leaves the system pool out on
// purpose, so CredHub must present a certificate that chains to a CA the
// platform put under CF_SYSTEM_CERT_PATH, and a CA in the app's rootfs is
// never enough. cf-deployment puts the CredHub CA there.
func credhubCAPool(dir string) (*x509.CertPool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s %s: %w", systemCertPathEnv, dir, err)
	}
	pool := x509.NewCertPool()
	found := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), credhubCAFileSuffix) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading the CA file %s: %w", path, err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("the CA file %s holds no PEM certificate", path)
		}
		found++
	}
	if found == 0 {
		return nil, fmt.Errorf("%s %s holds no %s CA file to verify CredHub with", systemCertPathEnv, dir, credhubCAFileSuffix)
	}
	return pool, nil
}

// credhubAttempt makes one interpolate request. It returns the response body
// and an empty reason on success, a reason class for a failed attempt, or a
// *signalledError when a signal on sigs cancels the request.
func credhubAttempt(client *http.Client, endpoint *url.URL, body []byte, sigs <-chan os.Signal) (services, reason string, err error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("building the CredHub request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	type result struct{ services, reason string }
	done := make(chan result, 1)
	go func() {
		s, r := credhubSend(client, req)
		done <- result{s, r}
	}()
	select {
	case r := <-done:
		return r.services, r.reason, nil
	case sig := <-sigs:
		// The request is cancelled, and the step waits for it to finish, so
		// nothing of it outlives the step.
		cancel()
		<-done
		return "", "", credhubSignalled(sig)
	}
}

// credhubSend makes one exchange. Specs wrap it to see when an exchange
// finishes.
var credhubSend = credhubExchange

// credhubExchange sends req and checks the response: a 2xx status and a body
// of at most maxGuestEnvBytes that is a JSON object. It returns the body, or
// the reason the attempt failed.
func credhubExchange(client *http.Client, req *http.Request) (services, reason string) {
	resp, err := client.Do(req)
	if err != nil {
		return "", credhubFailureReason(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxGuestEnvBytes+1))
	if err != nil {
		return "", "reading the response failed: " + credhubFailureReason(err)
	}
	if len(raw) > maxGuestEnvBytes {
		return "", fmt.Sprintf("the response is over %d bytes", maxGuestEnvBytes)
	}
	if !json.Valid(raw) || !bytes.HasPrefix(bytes.TrimLeft(raw, " \t\r\n"), []byte("{")) {
		return "", "the response is not a JSON object"
	}
	return string(raw), ""
}

// credhubFailureReason returns the fixed class of a transport error, which
// is all a log line says about it: Go's errors name the URL and can quote
// what the server sent.
func credhubFailureReason(err error) string {
	var dnsErr *net.DNSError
	var recordErr tls.RecordHeaderError
	var alertErr tls.AlertError
	var verifyErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	var opErr *net.OpError
	var netErr net.Error
	switch {
	case errors.As(err, &dnsErr):
		return "DNS lookup failed"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.As(err, &recordErr), errors.As(err, &alertErr), errors.As(err, &verifyErr),
		errors.As(err, &unknownAuthority), errors.As(err, &hostnameErr), errors.As(err, &invalidErr),
		errors.As(err, &opErr) && opErr.Op == "remote error":
		// crypto/tls reports an alert from the server, such as one that
		// rejects the client certificate, as a "remote error".
		return "TLS handshake failed"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timed out"
	}
	return "other transport error"
}
