//go:build linux && !(cgo && seccomp)

package guardiancmd

import (
	"fmt"
	"os"

	. "github.com/onsi/ginkgo/v2"
)

// requireLibseccompSpecs makes the missing libseccomp specs a failure.
const requireLibseccompSpecs = "GUARDIANCMD_REQUIRE_LIBSECCOMP_SPECS"

var _ = Describe("Garden's profiles as runc loads them with libseccomp", func() {
	It("needs a build with cgo, libseccomp, and -tags seccomp", func() {
		msg := fmt.Sprintf("VACUOUS LIBSECCOMP CHECK: this test binary was built without cgo and -tags seccomp, so nothing loads Garden's profiles through libseccomp. Build with CGO_ENABLED=1, libseccomp's headers, and -tags seccomp to run those specs, and set %s=1 to make this note a failure.", requireLibseccompSpecs)
		if os.Getenv(requireLibseccompSpecs) != "" {
			Fail(msg)
		}
		AddReportEntry("vacuous libseccomp check", msg)
		fmt.Fprintln(os.Stderr, msg)
	})
})
