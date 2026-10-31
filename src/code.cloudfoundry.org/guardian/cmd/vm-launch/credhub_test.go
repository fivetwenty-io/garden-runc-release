//go:build linux

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"code.cloudfoundry.org/guardian/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// testCert is a certificate and its key, parsed and as PEM.
type testCert struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
}

// newTestCert issues a certificate for template, signed by parent, or self
// signed when parent is nil.
func newTestCert(template *x509.Certificate, parent *testCert) testCert {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	Expect(err).NotTo(HaveOccurred())
	template.SerialNumber = serial
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(time.Hour)
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	keyDER, err := x509.MarshalECPrivateKey(key)
	Expect(err).NotTo(HaveOccurred())
	return testCert{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

func newTestCA(name string) testCert {
	return newTestCert(&x509.Certificate{
		Subject:               pkix.Name{CommonName: name},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}, nil)
}

// credhubRequest is what the fake CredHub saw of one request.
type credhubRequest struct {
	method      string
	path        string
	query       string
	contentType string
	body        []byte
	clientCN    string
}

// fakeCredHub is an HTTPS server that requires a client certificate signed
// by the instance identity CA, as CredHub does.
type fakeCredHub struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []credhubRequest
	respond  func(w http.ResponseWriter, r *http.Request, body []byte)
}

func (f *fakeCredHub) seen() []credhubRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]credhubRequest(nil), f.requests...)
}

// credhubFixture is a fake CredHub with its CA, the instance identity, and
// the files and environment vm-launch reads to reach it.
type credhubFixture struct {
	hub      *fakeCredHub
	serverCA testCert
	certDir  string
	env      map[string]string
	logBuf   *bytes.Buffer
	logger   *log.Logger
	retry    credhubRetry
	opts     credhubClientOptions
	sigs     chan os.Signal
}

// credhubRefServices is VCAP_SERVICES with one reference whose path holds
// the sentinel, so a leaked path shows up.
var credhubRefServices = `{"user-provided":[{"name":"db","credentials":{"credhub-ref":"/c/` + secretSentinel + `"}}]}`

// newCredhubFixture starts a fake CredHub whose certificate names serverDNS
// and serverIPs, and points VCAP_PLATFORM_OPTIONS at it by address.
func newCredhubFixture(serverDNS []string, serverIPs []net.IP) *credhubFixture {
	f := &credhubFixture{hub: &fakeCredHub{}, logBuf: &bytes.Buffer{}}
	f.logger = log.New(f.logBuf, "", 0)
	f.serverCA = newTestCA("credhub CA")
	identityCA := newTestCA("instance identity CA")
	server := newTestCert(&x509.Certificate{
		Subject:     pkix.Name{CommonName: "credhub"},
		DNSNames:    serverDNS,
		IPAddresses: serverIPs,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &f.serverCA)
	instance := newTestCert(&x509.Certificate{
		Subject:     pkix.Name{CommonName: "instance-guid"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, &identityCA)

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(identityCA.cert)
	serverPair, err := tls.X509KeyPair(server.certPEM, server.keyPEM)
	Expect(err).NotTo(HaveOccurred())

	hub := f.hub
	hub.respond = func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"user-provided":[{"name":"db","credentials":{"uri":"postgresql://u:`+secretSentinel+`@db.internal/app"}}]}`)
	}
	hub.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen := credhubRequest{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, contentType: r.Header.Get("Content-Type"), body: body}
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			seen.clientCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		hub.mu.Lock()
		hub.requests = append(hub.requests, seen)
		respond := hub.respond
		hub.mu.Unlock()
		respond(w, r, body)
	}))
	hub.server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	}
	hub.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	hub.server.StartTLS()
	DeferCleanup(hub.server.Close)

	dir := GinkgoT().TempDir()
	f.certDir = filepath.Join(dir, "system-certs")
	Expect(os.Mkdir(f.certDir, 0o755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(f.certDir, "credhub-ca.crt"), f.serverCA.certPEM, 0o644)).To(Succeed())
	certPath, keyPath := filepath.Join(dir, "instance.crt"), filepath.Join(dir, "instance.key")
	Expect(os.WriteFile(certPath, instance.certPEM, 0o644)).To(Succeed())
	Expect(os.WriteFile(keyPath, instance.keyPEM, 0o600)).To(Succeed())

	f.env = map[string]string{
		vcapServicesEnv:    credhubRefServices,
		platformOptionsEnv: `{"credhub-uri":"` + hub.server.URL + `"}`,
		instanceCertEnv:    certPath,
		instanceKeyEnv:     keyPath,
		systemCertPathEnv:  f.certDir,
		"VCAP_APPLICATION": `{"name":"app"}`,
	}
	f.retry = credhubRetry{attempts: 3, delay: time.Millisecond}
	f.opts = credhubClientOptions{timeout: 5 * time.Second}
	f.sigs = make(chan os.Signal, 1)
	return f
}

// newLocalCredhubFixture is a fake CredHub at 127.0.0.1 whose certificate
// matches that address.
func newLocalCredhubFixture() *credhubFixture {
	return newCredhubFixture(nil, []net.IP{net.IPv4(127, 0, 0, 1)})
}

func (f *credhubFixture) resolve() (string, bool, error) {
	return resolveCredhubRefs(lookupIn(f.env), f.retry, f.opts, f.sigs, f.logger)
}

func (f *credhubFixture) respondWith(respond func(w http.ResponseWriter, r *http.Request, body []byte)) {
	f.hub.mu.Lock()
	defer f.hub.mu.Unlock()
	f.hub.respond = respond
}

func (f *credhubFixture) host() string {
	u, err := url.Parse(f.hub.server.URL)
	Expect(err).NotTo(HaveOccurred())
	return u.Host
}

// failureLines are the log lines of n failed attempts to the fixture's host.
func (f *credhubFixture) failureLines(n int, reason string) string {
	var lines strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&lines, "resolving CredHub references: attempt %d of %d to %s failed: %s\n", i, f.retry.attempts, f.host(), reason)
	}
	return lines.String()
}

// expectNoLeak checks that err and the log never hold the sentinel, which
// is in the reference path, the response bodies, and the credentials.
func expectNoLeak(f *credhubFixture, err error) {
	if err != nil {
		Expect(err.Error()).NotTo(ContainSubstring(secretSentinel))
	}
	Expect(f.logBuf.String()).NotTo(ContainSubstring(secretSentinel))
	Expect(f.logBuf.String()).NotTo(ContainSubstring("/c/"))
}

var _ = Describe("CredHub interpolation", func() {
	var f *credhubFixture

	BeforeEach(func() {
		f = newLocalCredhubFixture()
	})

	Describe("when it runs", func() {
		DescribeTable("skips the step as the launcher does, without a request",
			func(change map[string]string, logLine string) {
				for name, value := range change {
					if value == "<unset>" {
						delete(f.env, name)
						continue
					}
					f.env[name] = value
				}
				services, resolved, err := f.resolve()
				Expect(err).NotTo(HaveOccurred())
				Expect(resolved).To(BeFalse())
				Expect(services).To(BeEmpty())
				Expect(f.hub.seen()).To(BeEmpty())
				Expect(f.logBuf.String()).To(Equal(logLine))
			},
			Entry("no credhub-ref", map[string]string{vcapServicesEnv: `{"db":[{"credentials":{"uri":"x"}}]}`}, ""),
			Entry("no VCAP_SERVICES", map[string]string{vcapServicesEnv: "<unset>"}, ""),
			Entry("credhub-ref without its quotes", map[string]string{vcapServicesEnv: `{"db":[{"credentials":{"note":"a credhub-ref here"}}]}`}, ""),
			Entry("CREDHUB_SKIP_INTERPOLATION", map[string]string{credhubSkipEnv: "true"}, ""),
			Entry("CREDHUB_SKIP_INTERPOLATION set to false, which is not empty", map[string]string{credhubSkipEnv: "false"}, ""),
			Entry("no VCAP_PLATFORM_OPTIONS", map[string]string{platformOptionsEnv: "<unset>"}, noCredhubURILine),
			Entry("empty VCAP_PLATFORM_OPTIONS", map[string]string{platformOptionsEnv: ""}, noCredhubURILine),
			Entry("platform options without credhub-uri", map[string]string{platformOptionsEnv: `{}`}, noCredhubURILine),
			Entry("platform options of null", map[string]string{platformOptionsEnv: `null`}, noCredhubURILine),
			Entry("an empty credhub-uri", map[string]string{platformOptionsEnv: `{"credhub-uri":""}`}, noCredhubURILine),
		)

		It("runs when CREDHUB_SKIP_INTERPOLATION is set but empty", func() {
			f.env[credhubSkipEnv] = ""
			_, resolved, err := f.resolve()
			Expect(err).NotTo(HaveOccurred())
			Expect(resolved).To(BeTrue())
			Expect(f.hub.seen()).To(HaveLen(1))
		})

		DescribeTable("rejects VCAP_PLATFORM_OPTIONS that is not valid JSON, as the launcher does, even when nothing needs resolving",
			func(change map[string]string) {
				f.env[platformOptionsEnv] = `{"credhub-uri":"` + secretSentinel
				for name, value := range change {
					f.env[name] = value
				}
				_, _, err := f.resolve()
				Expect(err).To(MatchError("VCAP_PLATFORM_OPTIONS is not valid JSON platform options"))
				Expect(stepExitCode(err)).To(Equal(exitLaunchError))
				Expect(f.hub.seen()).To(BeEmpty())
				expectNoLeak(f, err)
			},
			Entry("with a reference", map[string]string{}),
			Entry("without a reference", map[string]string{vcapServicesEnv: `{}`}),
			Entry("with CREDHUB_SKIP_INTERPOLATION", map[string]string{credhubSkipEnv: "true"}),
		)

		It("rejects a credhub-uri of the wrong type", func() {
			f.env[platformOptionsEnv] = `{"credhub-uri":5}`
			_, _, err := f.resolve()
			Expect(err).To(MatchError("VCAP_PLATFORM_OPTIONS is not valid JSON platform options"))
		})
	})

	Describe("a resolved reference", func() {
		It("posts VCAP_SERVICES to the interpolate endpoint with the instance identity and returns the response", func() {
			services, resolved, err := f.resolve()
			Expect(err).NotTo(HaveOccurred())
			Expect(resolved).To(BeTrue())
			Expect(services).To(Equal(`{"user-provided":[{"name":"db","credentials":{"uri":"postgresql://u:` + secretSentinel + `@db.internal/app"}}]}`))

			seen := f.hub.seen()
			Expect(seen).To(HaveLen(1))
			Expect(seen[0].method).To(Equal(http.MethodPost))
			Expect(seen[0].path).To(Equal("/api/v1/interpolate"))
			Expect(seen[0].query).To(BeEmpty())
			Expect(seen[0].contentType).To(Equal("application/json"))
			Expect(seen[0].clientCN).To(Equal("instance-guid"))
			// credhub-cli decodes VCAP_SERVICES and encodes it again.
			var sent, original map[string]any
			Expect(json.Unmarshal(seen[0].body, &sent)).To(Succeed())
			Expect(json.Unmarshal([]byte(credhubRefServices), &original)).To(Succeed())
			Expect(sent).To(Equal(original))
			reencoded, err := json.Marshal(original)
			Expect(err).NotTo(HaveOccurred())
			Expect(seen[0].body).To(Equal(reencoded))

			Expect(f.logBuf.String()).To(BeEmpty())
		})

		It("replaces any path and query in credhub-uri with the endpoint's", func() {
			f.env[platformOptionsEnv] = `{"credhub-uri":"` + f.hub.server.URL + `/some/base?x=1"}`
			_, resolved, err := f.resolve()
			Expect(err).NotTo(HaveOccurred())
			Expect(resolved).To(BeTrue())
			Expect(f.hub.seen()[0].path).To(Equal("/api/v1/interpolate"))
			Expect(f.hub.seen()[0].query).To(BeEmpty())
		})

		It("succeeds on a later attempt after failed ones", func() {
			calls := 0
			f.respondWith(func(w http.ResponseWriter, _ *http.Request, _ []byte) {
				calls++
				if calls < 3 {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				_, _ = io.WriteString(w, `{"resolved":true}`)
			})
			services, resolved, err := f.resolve()
			Expect(err).NotTo(HaveOccurred())
			Expect(resolved).To(BeTrue())
			Expect(services).To(Equal(`{"resolved":true}`))
			Expect(f.logBuf.String()).To(Equal(f.failureLines(2, "HTTP 503")))
		})

		It("accepts any 2xx status", func() {
			f.respondWith(func(w http.ResponseWriter, _ *http.Request, _ []byte) {
				w.WriteHeader(http.StatusAccepted)
				_, _ = io.WriteString(w, " \n{}")
			})
			services, resolved, err := f.resolve()
			Expect(err).NotTo(HaveOccurred())
			Expect(resolved).To(BeTrue())
			Expect(services).To(Equal(" \n{}"))
		})
	})

	Describe("trust", func() {
		It("trusts a CA only from a .crt file", func() {
			Expect(os.Rename(filepath.Join(f.certDir, "credhub-ca.crt"), filepath.Join(f.certDir, "credhub-ca.pem"))).To(Succeed())
			Expect(os.WriteFile(filepath.Join(f.certDir, "other.crt"), newTestCA("other CA").certPEM, 0o644)).To(Succeed())
			_, _, err := f.resolve()
			Expect(err).To(MatchError(fmt.Sprintf("resolving CredHub references at %s failed after 3 attempts", f.host())))
			Expect(f.logBuf.String()).To(Equal(f.failureLines(3, "TLS handshake failed")))
			Expect(f.hub.seen()).To(BeEmpty())
		})

		It("trusts only the files directly under CF_SYSTEM_CERT_PATH", func() {
			sub := filepath.Join(f.certDir, "nested.crt")
			Expect(os.Rename(filepath.Join(f.certDir, "credhub-ca.crt"), filepath.Join(f.certDir, "credhub-ca.pem"))).To(Succeed())
			Expect(os.WriteFile(filepath.Join(f.certDir, "other.crt"), newTestCA("other CA").certPEM, 0o644)).To(Succeed())
			Expect(os.Mkdir(sub, 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(sub, "credhub-ca.crt"), f.serverCA.certPEM, 0o644)).To(Succeed())
			_, _, err := f.resolve()
			Expect(err).To(MatchError(fmt.Sprintf("reading the CA file %s: read %s: is a directory", sub, sub)))
		})

		It("checks the server's name against the credhub-uri host", func() {
			other := newCredhubFixture([]string{"credhub.service.cf.internal"}, nil)
			_, _, err := other.resolve()
			Expect(err).To(HaveOccurred())
			Expect(other.logBuf.String()).To(Equal(other.failureLines(3, "TLS handshake failed")))
			Expect(other.hub.seen()).To(BeEmpty())
		})

		It("fails a CredHub that does not accept the instance identity", func() {
			f.hub.server.TLS.ClientCAs = x509.NewCertPool()
			f.hub.server.TLS.ClientCAs.AddCert(newTestCA("another identity CA").cert)
			_, _, err := f.resolve()
			Expect(err).To(HaveOccurred())
			Expect(f.logBuf.String()).To(Equal(f.failureLines(3, "TLS handshake failed")))
			Expect(f.hub.seen()).To(BeEmpty())
		})

		// Go's client already refuses TLS below 1.2 by default, so this spec
		// passes without the client's MinVersion. The next one checks the
		// setting itself, so that a change to Go's default or a GODEBUG
		// setting cannot lower the floor unnoticed.
		It("refuses TLS below 1.2", func() {
			f.hub.server.TLS.MinVersion = tls.VersionTLS10
			f.hub.server.TLS.MaxVersion = tls.VersionTLS11
			_, _, err := f.resolve()
			Expect(err).To(HaveOccurred())
			Expect(f.logBuf.String()).To(Equal(f.failureLines(3, "TLS handshake failed")))
		})

		It("sets a TLS 1.2 floor and roots of only the CA files, without the system pool", func() {
			client, err := newCredhubClient(func(name string) string { return f.env[name] }, f.opts)
			Expect(err).NotTo(HaveOccurred())
			transport, ok := client.Transport.(*http.Transport)
			Expect(ok).To(BeTrue())
			Expect(transport.TLSClientConfig.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
			// The expected pool comes from the test CA's PEM and not from
			// credhubCAPool, so a pool that starts from the system pool
			// does not equal it.
			want := x509.NewCertPool()
			Expect(want.AppendCertsFromPEM(f.serverCA.certPEM)).To(BeTrue())
			Expect(transport.TLSClientConfig.RootCAs.Equal(want)).To(BeTrue())
		})
	})

	Describe("failed attempts", func() {
		DescribeTable("retry an error status the configured number of times, naming only the status",
			func(status int) {
				f.respondWith(func(w http.ResponseWriter, _ *http.Request, _ []byte) {
					w.WriteHeader(status)
					_, _ = io.WriteString(w, `{"error":"The request includes an unrecognized parameter /c/`+secretSentinel+`"}`)
				})
				f.retry = credhubRetry{attempts: 4, delay: time.Millisecond}
				_, _, err := f.resolve()
				Expect(err).To(MatchError(fmt.Sprintf("resolving CredHub references at %s failed after 4 attempts", f.host())))
				Expect(stepExitCode(err)).To(Equal(exitLaunchError))
				Expect(f.hub.seen()).To(HaveLen(4))
				Expect(f.logBuf.String()).To(Equal(f.failureLines(4, fmt.Sprintf("HTTP %d", status))))
				expectNoLeak(f, err)
			},
			Entry("403", http.StatusForbidden),
			Entry("404", http.StatusNotFound),
			Entry("500", http.StatusInternalServerError),
		)

		It("never follows a redirect", func() {
			f.respondWith(func(w http.ResponseWriter, r *http.Request, _ []byte) {
				if r.URL.Path == "/elsewhere" {
					_, _ = io.WriteString(w, `{}`)
					return
				}
				http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
			})
			_, _, err := f.resolve()
			Expect(err).To(HaveOccurred())
			Expect(f.logBuf.String()).To(Equal(f.failureLines(3, "HTTP 307")))
			for _, r := range f.hub.seen() {
				Expect(r.path).To(Equal("/api/v1/interpolate"))
			}
		})

		DescribeTable("rejects a body that is not a JSON object",
			func(body string) {
				f.respondWith(func(w http.ResponseWriter, _ *http.Request, _ []byte) {
					_, _ = io.WriteString(w, body)
				})
				_, _, err := f.resolve()
				Expect(err).To(HaveOccurred())
				Expect(f.logBuf.String()).To(Equal(f.failureLines(3, "the response is not a JSON object")))
				expectNoLeak(f, err)
			},
			Entry("an array", `[{"`+secretSentinel+`":1}]`),
			Entry("a string", `"`+secretSentinel+`"`),
			Entry("null", `null`),
			Entry("invalid JSON", `{"`+secretSentinel),
			Entry("an object followed by more", `{} {}`),
			Entry("empty", ``),
		)

		It("takes a body of exactly 1 MiB and rejects a longer one", func() {
			exact := `{"a":"` + strings.Repeat("x", maxGuestEnvBytes-8) + `"}`
			Expect(exact).To(HaveLen(maxGuestEnvBytes))
			f.respondWith(func(w http.ResponseWriter, _ *http.Request, _ []byte) {
				_, _ = io.WriteString(w, exact)
			})
			services, resolved, err := f.resolve()
			Expect(err).NotTo(HaveOccurred())
			Expect(resolved).To(BeTrue())
			Expect(services).To(Equal(exact))

			f.respondWith(func(w http.ResponseWriter, _ *http.Request, _ []byte) {
				_, _ = io.WriteString(w, exact+" ")
			})
			_, _, err = f.resolve()
			Expect(err).To(HaveOccurred())
			Expect(f.logBuf.String()).To(Equal(f.failureLines(3, "the response is over 1048576 bytes")))
		})

		It("retries a refused connection with the configured delay", func() {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			Expect(err).NotTo(HaveOccurred())
			addr := l.Addr().String()
			Expect(l.Close()).To(Succeed())
			f.env[platformOptionsEnv] = `{"credhub-uri":"https://` + addr + `"}`
			f.retry = credhubRetry{attempts: 3, delay: 150 * time.Millisecond}

			start := time.Now()
			_, _, err = f.resolve()
			elapsed := time.Since(start)
			Expect(err).To(MatchError(fmt.Sprintf("resolving CredHub references at %s failed after 3 attempts", addr)))
			// Two delays: none follows the last attempt.
			Expect(elapsed).To(BeNumerically(">=", 300*time.Millisecond))
			Expect(elapsed).To(BeNumerically("<", 450*time.Millisecond))
			Expect(f.logBuf.String()).To(Equal(strings.Join([]string{
				"resolving CredHub references: attempt 1 of 3 to " + addr + " failed: connection refused",
				"resolving CredHub references: attempt 2 of 3 to " + addr + " failed: connection refused",
				"resolving CredHub references: attempt 3 of 3 to " + addr + " failed: connection refused",
			}, "\n") + "\n"))
		})

		It("times out an attempt that hangs", func() {
			release := make(chan struct{})
			DeferCleanup(func() { close(release) })
			f.respondWith(func(w http.ResponseWriter, r *http.Request, _ []byte) {
				select {
				case <-release:
				case <-r.Context().Done():
				}
			})
			f.retry = credhubRetry{attempts: 2, delay: time.Millisecond}
			f.opts.timeout = 200 * time.Millisecond
			_, _, err := f.resolve()
			Expect(err).To(HaveOccurred())
			Expect(f.logBuf.String()).To(Equal(f.failureLines(2, "timed out")))
		})

		It("names a failed DNS lookup", func() {
			f.env[platformOptionsEnv] = `{"credhub-uri":"https://credhub.does-not-exist.invalid:8844"}`
			f.retry = credhubRetry{attempts: 1, delay: time.Millisecond}
			_, _, err := f.resolve()
			Expect(err).To(MatchError("resolving CredHub references at credhub.does-not-exist.invalid:8844 failed after 1 attempts"))
			Expect(f.logBuf.String()).To(Equal("resolving CredHub references: attempt 1 of 1 to credhub.does-not-exist.invalid:8844 failed: DNS lookup failed\n"))
		})
	})

	Describe("inputs it cannot use", func() {
		DescribeTable("fail before any request",
			func(prepare func(f *credhubFixture), msg string) {
				prepare(f)
				_, _, err := f.resolve()
				Expect(err).To(MatchError(MatchRegexp(msg)))
				Expect(stepExitCode(err)).To(Equal(exitLaunchError))
				Expect(f.hub.seen()).To(BeEmpty())
				Expect(f.logBuf.String()).To(BeEmpty())
				expectNoLeak(f, err)
			},
			Entry("no CF_INSTANCE_CERT", func(f *credhubFixture) { delete(f.env, instanceCertEnv) },
				`^a service binding holds a CredHub reference, and CF_INSTANCE_CERT or CF_INSTANCE_KEY is not set$`),
			Entry("an empty CF_INSTANCE_KEY", func(f *credhubFixture) { f.env[instanceKeyEnv] = "" },
				`^a service binding holds a CredHub reference, and CF_INSTANCE_CERT or CF_INSTANCE_KEY is not set$`),
			Entry("no CF_SYSTEM_CERT_PATH", func(f *credhubFixture) { delete(f.env, systemCertPathEnv) },
				`^a service binding holds a CredHub reference, and CF_SYSTEM_CERT_PATH is not set$`),
			Entry("a missing certificate file", func(f *credhubFixture) { f.env[instanceCertEnv] = "/nonexistent/instance.crt" },
				`^reading the instance certificate /nonexistent/instance.crt: open /nonexistent/instance.crt: no such file or directory$`),
			Entry("a missing key file", func(f *credhubFixture) { f.env[instanceKeyEnv] = "/nonexistent/instance.key" },
				`^reading the instance key /nonexistent/instance.key: open /nonexistent/instance.key: no such file or directory$`),
			Entry("a key that does not match the certificate", func(f *credhubFixture) {
				Expect(os.WriteFile(f.env[instanceKeyEnv], newTestCA("x").keyPEM, 0o600)).To(Succeed())
			}, `^loading the instance identity from \S+ and \S+: tls: private key does not match public key$`),
			Entry("a missing CA directory", func(f *credhubFixture) { f.env[systemCertPathEnv] = "/nonexistent/certs" },
				`^reading CF_SYSTEM_CERT_PATH /nonexistent/certs: open /nonexistent/certs: no such file or directory$`),
			Entry("a CA directory without a .crt file", func(f *credhubFixture) {
				Expect(os.Rename(filepath.Join(f.certDir, "credhub-ca.crt"), filepath.Join(f.certDir, "credhub-ca.pem"))).To(Succeed())
			}, `^CF_SYSTEM_CERT_PATH \S+ holds no \.crt CA file to verify CredHub with$`),
			Entry("a .crt file that holds no certificate", func(f *credhubFixture) {
				Expect(os.WriteFile(filepath.Join(f.certDir, "broken.crt"), []byte(secretSentinel), 0o644)).To(Succeed())
			}, `^the CA file \S+/broken\.crt holds no PEM certificate$`),
			Entry("an http credhub-uri", func(f *credhubFixture) {
				f.env[platformOptionsEnv] = `{"credhub-uri":"http://127.0.0.1:1"}`
			}, `^the credhub-uri in VCAP_PLATFORM_OPTIONS must be an https URL with a host$`),
			Entry("a credhub-uri without a host", func(f *credhubFixture) {
				f.env[platformOptionsEnv] = `{"credhub-uri":"https:///api"}`
			}, `^the credhub-uri in VCAP_PLATFORM_OPTIONS must be an https URL with a host$`),
			Entry("a credhub-uri with user information", func(f *credhubFixture) {
				f.env[platformOptionsEnv] = `{"credhub-uri":"https://u:` + secretSentinel + `@127.0.0.1:1"}`
			}, `^the credhub-uri in VCAP_PLATFORM_OPTIONS must not hold user information$`),
			Entry("a credhub-uri that does not parse", func(f *credhubFixture) {
				f.env[platformOptionsEnv] = `{"credhub-uri":"https://127.0.0.1:1/` + "\\u007f" + secretSentinel + `"}`
			}, `^the credhub-uri in VCAP_PLATFORM_OPTIONS is not a valid URL$`),
			Entry("VCAP_SERVICES that is not valid JSON", func(f *credhubFixture) {
				f.env[vcapServicesEnv] = `{"credhub-ref":"/c/` + secretSentinel
			}, `^VCAP_SERVICES is not valid JSON, so its CredHub references cannot be resolved$`),
		)
	})

	Describe("signals", func() {
		// signalOnLog is a log writer that sends sig on sigs at the first line
		// that holds marker.
		type signalOnLog struct {
			buf    *bytes.Buffer
			marker string
			sig    os.Signal
			sigs   chan<- os.Signal
			sent   bool
		}

		// signalAtLog makes the fixture's logger send sig at the first line
		// that holds marker.
		signalAtLog := func(marker string, sig os.Signal) {
			w := &signalOnLog{buf: f.logBuf, marker: marker, sig: sig, sigs: f.sigs}
			f.logger = log.New(writerFunc(func(p []byte) (int, error) {
				if !w.sent && bytes.Contains(p, []byte(w.marker)) {
					w.sent = true
					w.sigs <- w.sig
				}
				return w.buf.Write(p)
			}), "", 0)
		}

		It("stops in the retry delay at a SIGTERM without waiting for the remaining attempts", func() {
			f.respondWith(func(w http.ResponseWriter, _ *http.Request, _ []byte) {
				w.WriteHeader(http.StatusInternalServerError)
			})
			f.retry = credhubRetry{attempts: 5, delay: time.Hour}
			signalAtLog("attempt 1 of 5", syscall.SIGTERM)

			start := time.Now()
			_, _, err := f.resolve()
			Expect(time.Since(start)).To(BeNumerically("<", 10*time.Second))
			Expect(err).To(MatchError("received terminated while resolving CredHub references"))
			Expect(stepExitCode(err)).To(Equal(143))
			Expect(f.hub.seen()).To(HaveLen(1))
			Expect(f.logBuf.String()).To(Equal(fmt.Sprintf("resolving CredHub references: attempt 1 of 5 to %s failed: HTTP 500\n", f.host())))
		})

		It("exits for a SIGTERM that arrives while the last attempt fails", func() {
			f.respondWith(func(w http.ResponseWriter, _ *http.Request, _ []byte) {
				w.WriteHeader(http.StatusInternalServerError)
			})
			f.retry = credhubRetry{attempts: 1, delay: time.Hour}
			signalAtLog("attempt 1 of 1", syscall.SIGTERM)

			_, _, err := f.resolve()
			Expect(err).To(MatchError("received terminated while resolving CredHub references"))
			Expect(stepExitCode(err)).To(Equal(143))
			Expect(f.hub.seen()).To(HaveLen(1))
			Expect(f.logBuf.String()).To(Equal(fmt.Sprintf("resolving CredHub references: attempt 1 of 1 to %s failed: HTTP 500\n", f.host())))
		})

		It("cancels a request in flight at a SIGINT, and waits for it to finish", func() {
			// The exchange reports that it finished a little after the
			// cancelled request returns, so a step that stopped waiting for it
			// would return first.
			orig := credhubSend
			DeferCleanup(func() { credhubSend = orig })
			var finished atomic.Bool
			credhubSend = func(client *http.Client, req *http.Request) (string, string) {
				services, reason := orig(client, req)
				time.Sleep(200 * time.Millisecond)
				finished.Store(true)
				return services, reason
			}

			arrived := make(chan struct{}, 1)
			f.respondWith(func(w http.ResponseWriter, r *http.Request, _ []byte) {
				arrived <- struct{}{}
				<-r.Context().Done()
			})
			go func() {
				defer GinkgoRecover()
				Eventually(arrived).Should(Receive())
				f.sigs <- syscall.SIGINT
			}()
			start := time.Now()
			_, _, err := f.resolve()
			Expect(time.Since(start)).To(BeNumerically("<", 4*time.Second))
			Expect(err).To(MatchError("received interrupt while resolving CredHub references"))
			Expect(finished.Load()).To(BeTrue(), "the step returned before the cancelled request finished")
			Expect(stepExitCode(err)).To(Equal(130))
			Expect(f.logBuf.String()).To(BeEmpty())
		})
	})

	It("goes through the proxy the proxy function picks", func() {
		var mu sync.Mutex
		var connects []string
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			mu.Lock()
			connects = append(connects, r.Host)
			mu.Unlock()
			upstream, err := net.Dial("tcp", r.Host)
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			w.WriteHeader(http.StatusOK)
			conn, rw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				upstream.Close()
				return
			}
			go func() {
				_, _ = io.Copy(upstream, rw)
				upstream.Close()
			}()
			_, _ = io.Copy(conn, upstream)
			conn.Close()
		}))
		DeferCleanup(proxy.Close)
		proxyURL, err := url.Parse(proxy.URL)
		Expect(err).NotTo(HaveOccurred())
		f.opts.proxy = http.ProxyURL(proxyURL)

		_, resolved, err := f.resolve()
		Expect(err).NotTo(HaveOccurred())
		Expect(resolved).To(BeTrue())
		mu.Lock()
		defer mu.Unlock()
		Expect(connects).To(Equal([]string{f.host()}))
	})

	DescribeTable("names the class of a transport error and nothing of its text",
		func(err error, reason string) {
			Expect(credhubFailureReason(err)).To(Equal(reason))
		},
		Entry("DNS", &url.Error{Op: "Post", URL: "https://x/" + secretSentinel, Err: &net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", Name: "x"}}}, "DNS lookup failed"),
		Entry("refused", &url.Error{Op: "Post", Err: &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}}, "connection refused"),
		Entry("unknown authority", &url.Error{Op: "Post", Err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}}, "TLS handshake failed"),
		Entry("hostname", &url.Error{Op: "Post", Err: x509.HostnameError{Certificate: &x509.Certificate{}, Host: "x"}}, "TLS handshake failed"),
		Entry("a record that is not TLS", &url.Error{Op: "Post", Err: tls.RecordHeaderError{Msg: secretSentinel}}, "TLS handshake failed"),
		Entry("an alert from the server", &url.Error{Op: "Post", Err: &net.OpError{Op: "remote error", Err: errors.New("tls: certificate required")}}, "TLS handshake failed"),
		Entry("a timeout", &url.Error{Op: "Post", Err: timeoutError{}}, "timed out"),
		Entry("anything else", &url.Error{Op: "Post", Err: errors.New(secretSentinel)}, "other transport error"),
	)
})

// timeoutError is a net.Error that timed out.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

const noCredhubURILine = "a service binding holds a CredHub reference, and VCAP_PLATFORM_OPTIONS names no credhub-uri to resolve it; the guest gets the reference unresolved\n"

var _ = Describe("the launcher's CredHub flags", func() {
	DescribeTable("parse as the launcher parses its arguments after START-COMMAND",
		func(args []string, want credhubRetry) {
			got, err := credhubRetryFromArgs(args)
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(want))
		},
		Entry("no arguments", []string{}, credhubRetry{attempts: 3, delay: time.Second}),
		Entry("empty METADATA, as Diego passes it", []string{""}, credhubRetry{attempts: 3, delay: time.Second}),
		Entry("METADATA, which stops the parse", []string{`{"process_type":"web"}`, "-credhubConnectAttempts=9"}, credhubRetry{attempts: 3, delay: time.Second}),
		Entry("both flags", []string{"-credhubConnectAttempts=5", "-credhubRetryDelay=250ms"}, credhubRetry{attempts: 5, delay: 250 * time.Millisecond}),
		Entry("double dashes and separate values", []string{"--credhubConnectAttempts", "2", "--credhubRetryDelay", "0s", "{}"}, credhubRetry{attempts: 2, delay: 0}),
	)

	DescribeTable("reject what the launcher could not use",
		func(args []string, msg string) {
			_, err := credhubRetryFromArgs(args)
			Expect(err).To(MatchError(ContainSubstring(msg)))
			Expect(errors.Is(err, flag.ErrHelp)).To(BeFalse())
		},
		Entry("an attempt count that does not parse", []string{"-credhubConnectAttempts=many"}, `invalid value "many" for flag -credhubConnectAttempts`),
		Entry("a delay that does not parse", []string{"-credhubRetryDelay=soon"}, `invalid value "soon" for flag -credhubRetryDelay`),
		Entry("zero attempts", []string{"-credhubConnectAttempts=0"}, "-credhubConnectAttempts must be at least 1, got 0"),
		Entry("a negative delay", []string{"-credhubRetryDelay=-1s"}, "-credhubRetryDelay must not be negative, got -1s"),
		Entry("an unknown flag", []string{"-credhubProxy=x"}, "flag provided but not defined: -credhubProxy"),
		Entry("help", []string{"-h"}, "parsing the launcher's CredHub flags: flag: help requested"),
	)

	It("reaches the config through parseArgs, and only from the CF launcher's argv", func() {
		cfg, err := parseArgs([]string{"--backend", "vm-qemu", "--", "/tmp/lifecycle/launcher", "app", "true", "-credhubConnectAttempts=7", "-credhubRetryDelay=2s"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.credhub).To(Equal(credhubRetry{attempts: 7, delay: 2 * time.Second}))

		cfg, err = parseArgs([]string{"--backend", "vm-qemu", "--", "sh", "-credhubConnectAttempts=7"})
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.credhub).To(Equal(defaultCredhubRetry))

		_, err = parseArgs([]string{"--backend", "vm-qemu", "--", "/tmp/lifecycle/launcher", "app", "true", "-credhubConnectAttempts=x"})
		Expect(err).To(MatchError(ContainSubstring("parsing the launcher's CredHub flags")))
	})
})

var _ = Describe("run with CredHub references", func() {
	var (
		f      *credhubFixture
		art    string
		tmp    string
		logBuf *bytes.Buffer
	)

	BeforeEach(func() {
		f = newLocalCredhubFixture()
		art = makeArtifacts()
		logBuf = &bytes.Buffer{}
		for name, value := range f.env {
			GinkgoT().Setenv(name, value)
		}
		GinkgoT().Setenv("MEMORY_LIMIT", "512m")
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", tmp)
	})

	runVMOn := func(kind backend.Kind, launcherArgs ...string) int {
		argv := append([]string{"--backend", string(kind), "--artifacts", art, "--", "/tmp/lifecycle/launcher", "app", "true"}, launcherArgs...)
		return run(argv, log.New(logBuf, "", 0))
	}
	runVM := func(launcherArgs ...string) int {
		return runVMOn(backend.VMQemu, launcherArgs...)
	}

	It("gives the guest the resolved VCAP_SERVICES and the DATABASE_URL from it on both backends, and puts them nowhere else", func() {
		scratch := f.certDir + ".out"
		Expect(os.Mkdir(scratch, 0o755)).To(Succeed())
		for i, kind := range []backend.Kind{backend.VMQemu, backend.VMFirecracker} {
			hv := "qemu/ld-linux-x86-64.so.2"
			if kind == backend.VMFirecracker {
				hv = "firecracker/firecracker"
			}
			// Firecracker's config file is under TMPDIR while the hypervisor
			// runs, so the TMPDIR check covers it.
			initrdCopy := filepath.Join(scratch, string(kind)+".initrd")
			writeFakeHypervisor(filepath.Join(art, hv), `cat "$initrd" > `+shellQuote(initrdCopy)+`
! grep -r -q -F `+shellQuote(secretSentinel)+` `+shellQuote(tmp)+` || { echo "sentinel under TMPDIR" >&2; exit 1; }
! env | grep -q -F `+shellQuote(secretSentinel)+` || { echo "sentinel in the hypervisor environment" >&2; exit 1; }
! printf '%s\n' "$@" | grep -q -F `+shellQuote(secretSentinel)+` || { echo "sentinel in the hypervisor argv" >&2; exit 1; }
`)
			Expect(runVMOn(kind, "")).To(Equal(0), "%s: %s", kind, logBuf.String())
			Expect(f.hub.seen()).To(HaveLen(i+1), string(kind))

			raw, err := os.ReadFile(initrdCopy)
			Expect(err).NotTo(HaveOccurred())
			_, byName := archiveEntries(raw)
			envPath := filepath.Join(scratch, string(kind)+".env")
			Expect(os.WriteFile(envPath, byName["rvm/env"].data, 0o600)).To(Succeed())
			got := sourceAndDumpEnv([]string{"/bin/sh"}, envPath)
			Expect(got).To(HaveKeyWithValue("VCAP_SERVICES", `{"user-provided":[{"name":"db","credentials":{"uri":"postgresql://u:`+secretSentinel+`@db.internal/app"}}]}`), string(kind))
			// The uri exists only in the response, so DATABASE_URL proves the
			// references were resolved first.
			Expect(got).To(HaveKeyWithValue("DATABASE_URL", "postgres://u:"+secretSentinel+"@db.internal/app"), string(kind))
			for _, name := range []string{instanceCertEnv, instanceKeyEnv, systemCertPathEnv, platformOptionsEnv} {
				Expect(got).NotTo(HaveKey(name), "%s %s", kind, name)
			}
			Expect(logBuf.String()).NotTo(ContainSubstring(secretSentinel), string(kind))
			Expect(os.ReadDir(tmp)).To(BeEmpty(), string(kind))
		}
	})

	It("gives the guest the reference unresolved with CREDHUB_SKIP_INTERPOLATION", func() {
		scratch := f.certDir + ".out"
		Expect(os.Mkdir(scratch, 0o755)).To(Succeed())
		initrdCopy := filepath.Join(scratch, "initrd")
		writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), `cat "$initrd" > `+shellQuote(initrdCopy)+"\n")
		GinkgoT().Setenv(credhubSkipEnv, "true")
		Expect(runVM("")).To(Equal(0), logBuf.String())
		Expect(f.hub.seen()).To(BeEmpty())

		raw, err := os.ReadFile(initrdCopy)
		Expect(err).NotTo(HaveOccurred())
		_, byName := archiveEntries(raw)
		envPath := filepath.Join(scratch, "env")
		Expect(os.WriteFile(envPath, byName["rvm/env"].data, 0o600)).To(Succeed())
		got := sourceAndDumpEnv([]string{"/bin/sh"}, envPath)
		Expect(got).To(HaveKeyWithValue("VCAP_SERVICES", credhubRefServices))
		Expect(got).To(HaveKeyWithValue(credhubSkipEnv, "true"))
		Expect(got).NotTo(HaveKey("DATABASE_URL"))
	})

	It("exits 125 when every attempt fails, before the hypervisor runs, and never logs the error body", func() {
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		f.respondWith(func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"error":"`+secretSentinel+`"}`)
		})
		Expect(runVM("-credhubConnectAttempts=2", "-credhubRetryDelay=1ms")).To(Equal(exitLaunchError))
		Expect(f.hub.seen()).To(HaveLen(2))
		Expect(logBuf.String()).To(Equal(fmt.Sprintf("resolving CredHub references: attempt 1 of 2 to %[1]s failed: HTTP 500\n"+
			"resolving CredHub references: attempt 2 of 2 to %[1]s failed: HTTP 500\n"+
			"resolving CredHub references at %[1]s failed after 2 attempts\n", f.host())))
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(os.ReadDir(tmp)).To(BeEmpty())
	})

	It("exits 125 for a bad CredHub flag before any request", func() {
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		Expect(runVM("-credhubRetryDelay=soon")).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(ContainSubstring(`parsing the launcher's CredHub flags: invalid value "soon" for flag -credhubRetryDelay`))
		Expect(f.hub.seen()).To(BeEmpty())
		Expect(argvFile).NotTo(BeAnExistingFile())
	})

	It("exits 125 for VCAP_PLATFORM_OPTIONS that is not valid JSON", func() {
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		GinkgoT().Setenv(platformOptionsEnv, "{"+secretSentinel)
		Expect(runVM("")).To(Equal(exitLaunchError))
		Expect(logBuf.String()).To(Equal("VCAP_PLATFORM_OPTIONS is not valid JSON platform options\n"))
		Expect(argvFile).NotTo(BeAnExistingFile())
	})

	It("refuses an NFS mount it cannot fence before CredHub is asked, before the ports and the work directory", func() {
		// Something else holds the app's port. A launch that reserved the
		// ports before it refused the mount would stop on the port instead,
		// with the port's own line and not the mount's.
		held, err := net.Listen("tcp", "0.0.0.0:0")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(held.Close)
		port := held.Addr().(*net.TCPAddr).Port
		for name, c := range map[string]struct{ fstype, options, want string }{
			"mapfs":                  {"fuse.mapfs", "rw", "mapfs keeps flock local to each cell"},
			"NFSv3":                  {"nfs", "rw,vers=3", "a kernel NFSv3 mount"},
			"NFSv4 without the lock": {"nfs4", "rw,vers=4.1", "mount the share with local_lock=none"},
		} {
			volDir := GinkgoT().TempDir()
			DeferCleanup(func(saved string) { mountInfoPath = saved }, mountInfoPath)
			mountInfoPath = writeTempFile("mountinfo", nfsMountinfoLine(40, volDir, c.fstype, "10.0.0.5:/export", c.options))
			argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
			GinkgoT().Setenv("CF_INSTANCE_INDEX", "0")
			GinkgoT().Setenv("PORT", strconv.Itoa(port))
			GinkgoT().Setenv("VCAP_APPLICATION", vcapApp)
			GinkgoT().Setenv(vcapServicesEnv, `{"nfs":[{"name":"vol","credentials":{"credhub-ref":"/c/`+secretSentinel+`"},"volume_mounts":[`+mountJSON(volDir, "rw")+`]}]}`)
			logBuf.Reset()

			Expect(runVM("-credhubConnectAttempts=1")).To(Equal(exitLaunchError), name)
			Expect(logBuf.String()).To(ContainSubstring(c.want), name)
			Expect(f.hub.seen()).To(BeEmpty(), "%s: CredHub was asked", name)
			Expect(logBuf.String()).NotTo(ContainSubstring(portConflictMessage(port)), "%s: the port was reserved", name)
			Expect(logBuf.String()).NotTo(ContainSubstring("reserving port"), "%s: the port was reserved", name)
			entries, err := os.ReadDir(tmp)
			Expect(err).NotTo(HaveOccurred())
			for _, e := range entries {
				Expect(e.Name()).NotTo(HavePrefix("vm-launch-"), "%s: the work directory was made", name)
			}
			Expect(os.ReadDir(volDir)).To(BeEmpty(), name)
			Expect(argvFile).NotTo(BeAnExistingFile())
			Expect(logBuf.String()).NotTo(ContainSubstring(secretSentinel), name)
		}
	})

	It("fails before it opens or creates a volume image", func() {
		volDir := GinkgoT().TempDir()
		DeferCleanup(func(saved string) { mountInfoPath = saved }, mountInfoPath)
		mountInfoPath = writeTempFile("mountinfo", mountinfoLine(40, volDir, "fuse.juicefs"))
		argvFile := writeFakeHypervisor(filepath.Join(art, "qemu/ld-linux-x86-64.so.2"), "")
		GinkgoT().Setenv("CF_INSTANCE_INDEX", "0")
		GinkgoT().Setenv("VCAP_APPLICATION", vcapApp)
		GinkgoT().Setenv(vcapServicesEnv, `{"juicefs":[{"name":"vol","credentials":{"credhub-ref":"/c/`+secretSentinel+`"},"volume_mounts":[`+mountJSON(volDir, "rw")+`]}]}`)
		f.respondWith(func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			w.WriteHeader(http.StatusForbidden)
		})
		Expect(runVM("-credhubConnectAttempts=1")).To(Equal(exitLaunchError))
		Expect(f.hub.seen()).To(HaveLen(1))
		Expect(os.ReadDir(volDir)).To(BeEmpty())
		Expect(argvFile).NotTo(BeAnExistingFile())
		Expect(logBuf.String()).NotTo(ContainSubstring(secretSentinel))
	})
})
