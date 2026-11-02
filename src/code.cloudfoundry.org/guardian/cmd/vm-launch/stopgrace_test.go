//go:build linux

package main

import (
	"bytes"
	"log"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("the stop timing that Diego's interval gives", func() {
	var logBuf *bytes.Buffer

	timing := func(env map[string]string) (time.Duration, time.Duration) {
		return stopTiming(lookupIn(env), log.New(logBuf, "", 0))
	}

	BeforeEach(func() { logBuf = &bytes.Buffer{} })

	It("keeps the fixed deadline and wind-down without the variable, and for an empty one", func() {
		for _, env := range []map[string]string{nil, {stopGraceEnv: ""}} {
			deadline, windDown := timing(env)
			Expect(deadline).To(Equal(stopDeadline))
			Expect(windDown).To(Equal(guestWindDown))
		}
		Expect(logBuf.String()).To(BeEmpty())
	})

	It("matches the fixed values for Diego's default interval of 10 seconds", func() {
		deadline, windDown := timing(map[string]string{stopGraceEnv: "10"})
		Expect(deadline).To(Equal(stopDeadline))
		Expect(windDown).To(Equal(guestWindDown))
		Expect(logBuf.String()).To(BeEmpty())
	})

	It("keeps 2 seconds of the interval for the host and 2 more for the guest", func() {
		deadline, windDown := timing(map[string]string{stopGraceEnv: "30"})
		Expect(deadline).To(Equal(28 * time.Second))
		Expect(windDown).To(Equal(26 * time.Second))
	})

	It("ignores a value that is not a positive whole number of seconds, and says so", func() {
		for _, raw := range []string{"0", "-5", "ten", "1.5", "10s", " 10"} {
			logBuf.Reset()
			deadline, windDown := timing(map[string]string{stopGraceEnv: raw})
			Expect(deadline).To(Equal(stopDeadline), raw)
			Expect(windDown).To(Equal(guestWindDown), raw)
			Expect(logBuf.String()).To(ContainSubstring("ignoring " + stopGraceEnv + "=" + strconv.Quote(raw)))
		}
	})

	It("raises an interval under the minimum and lowers one over the maximum, and says so", func() {
		deadline, windDown := timing(map[string]string{stopGraceEnv: "3"})
		Expect(deadline).To(Equal(minStopGrace - stopGraceMargin))
		Expect(windDown).To(Equal(minStopGrace - 2*stopGraceMargin))
		Expect(logBuf.String()).To(ContainSubstring("under the 6s"))

		logBuf.Reset()
		deadline, _ = timing(map[string]string{stopGraceEnv: "86400"})
		Expect(deadline).To(Equal(maxStopGrace - stopGraceMargin))
		Expect(logBuf.String()).To(ContainSubstring("over the 10m0s"))
	})

	It("leaves a window for the volume teardown even at the minimum interval", func() {
		deadline, windDown := timing(map[string]string{stopGraceEnv: "1"})
		volumeWindDown := windDown - (guestWindDown - guestVolumeWindDown)
		Expect(volumeWindDown).To(BeNumerically(">=", time.Second))
		Expect(volumeWindDown + guestTeardownKillWait + stopGraceMargin).To(BeNumerically("<=", deadline))
	})

	It("keeps the guest from getting the variable", func() {
		Expect(guestEnvDenylist).To(HaveKey(stopGraceEnv))
		Expect(stackGuestEnvDenylist).To(HaveKey(stopGraceEnv))
	})

	Describe("in the stack guest's stage 2", func() {
		It("winds down at the guest's default without a wind-down, and uses the given one with it", func() {
			s := &guestStack{sidecars: []guestSidecar{{argv: "'sidecar'"}}}
			Expect(s.initScriptWithVolumes(testNonce, false)).To(ContainSubstring("sleep " + guestTimeoutSeconds + " &\n"))
			s.windDown = 26 * time.Second
			script := s.initScriptWithVolumes(testNonce, false)
			Expect(script).To(ContainSubstring("sleep 26 &\n"))
			Expect(script).NotTo(ContainSubstring("sleep " + guestTimeoutSeconds + " &\n"))
		})

		It("takes the volume teardown's second off a guest with volumes", func() {
			s := &guestStack{sidecars: []guestSidecar{{argv: "'sidecar'"}}, windDown: 26 * time.Second}
			Expect(s.initScriptWithVolumes(testNonce, true)).To(ContainSubstring("sleep 25 &\n"))
			s.windDown = 0
			Expect(s.initScriptWithVolumes(testNonce, true)).To(ContainSubstring("sleep " + guestVolumeTimeoutSeconds + " &\n"))
		})
	})
})
