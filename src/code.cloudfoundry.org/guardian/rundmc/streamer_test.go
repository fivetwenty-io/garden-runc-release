package rundmc_test

import (
	"errors"
	"io"
	"strings"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/garden/gardenfakes"
	"code.cloudfoundry.org/guardian/rundmc"
	fakes "code.cloudfoundry.org/guardian/rundmc/rundmcfakes"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/lager/v3/lagertest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var _ = Describe("NstarStreamer", func() {
	var (
		fakeOCIRuntime  *fakes.FakeOCIRuntime
		fakeNstarRunner *fakes.FakeNstarRunner
		logger          lager.Logger
		streamer        *rundmc.NstarStreamer
	)

	BeforeEach(func() {
		fakeOCIRuntime = new(fakes.FakeOCIRuntime)
		fakeNstarRunner = new(fakes.FakeNstarRunner)
		logger = lagertest.NewTestLogger("test")
		streamer = rundmc.NewNstarStreamer(fakeOCIRuntime, fakeNstarRunner)
		fakeOCIRuntime.StateReturns(rundmc.State{Pid: 42}, nil)
	})

	It("streams in with nstar against the init pid", func() {
		stream := gbytes.NewBuffer()
		Expect(streamer.StreamIn(logger, "handle", garden.StreamInSpec{Path: "/p", User: "u", TarStream: stream})).To(Succeed())

		_, handle := fakeOCIRuntime.StateArgsForCall(0)
		Expect(handle).To(Equal("handle"))
		_, pid, path, user, actualStream := fakeNstarRunner.StreamInArgsForCall(0)
		Expect(pid).To(Equal(42))
		Expect(path).To(Equal("/p"))
		Expect(user).To(Equal("u"))
		Expect(actualStream).To(Equal(stream))
	})

	It("streams out with nstar against the init pid", func() {
		fakeNstarRunner.StreamOutReturns(io.NopCloser(strings.NewReader("tar")), nil)
		_, err := streamer.StreamOut(logger, "handle", garden.StreamOutSpec{Path: "/p", User: "u"})
		Expect(err).NotTo(HaveOccurred())

		_, pid, path, user := fakeNstarRunner.StreamOutArgsForCall(0)
		Expect(pid).To(Equal(42))
		Expect(path).To(Equal("/p"))
		Expect(user).To(Equal("u"))
	})
})

var _ = Describe("ExecStreamer", func() {
	var (
		fakeOCIRuntime *fakes.FakeOCIRuntime
		logger         lager.Logger
		streamer       *rundmc.ExecStreamer
	)

	BeforeEach(func() {
		fakeOCIRuntime = new(fakes.FakeOCIRuntime)
		logger = lagertest.NewTestLogger("test")
		streamer = rundmc.NewExecStreamer(fakeOCIRuntime)
		fakeOCIRuntime.ExecReturns(new(gardenfakes.FakeProcess), nil)
	})

	Describe("StreamIn", func() {
		It("creates the destination and extracts the stream with the container's tar", func() {
			stream := gbytes.NewBuffer()
			Expect(streamer.StreamIn(logger, "handle", garden.StreamInSpec{Path: "/dest", User: "vcap", TarStream: stream})).To(Succeed())

			Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(2))

			_, handle, mkdirSpec, mkdirIO := fakeOCIRuntime.ExecArgsForCall(0)
			Expect(handle).To(Equal("handle"))
			Expect(mkdirSpec.Path).To(Equal("/bin/mkdir"))
			Expect(mkdirSpec.Args).To(Equal([]string{"-p", "/dest"}))
			Expect(mkdirSpec.User).To(Equal("vcap"))
			Expect(mkdirIO.Stdin).To(BeNil())

			_, handle, tarSpec, tarIO := fakeOCIRuntime.ExecArgsForCall(1)
			Expect(handle).To(Equal("handle"))
			Expect(tarSpec.Path).To(Equal("/bin/tar"))
			Expect(tarSpec.Args).To(Equal([]string{"--no-same-owner", "--no-same-permissions", "-xf", "-", "-C", "/dest"}))
			Expect(tarSpec.User).To(Equal("vcap"))
			Expect(tarIO.Stdin).To(Equal(stream))
		})

		It("runs as root when no user is given", func() {
			Expect(streamer.StreamIn(logger, "handle", garden.StreamInSpec{Path: "/dest"})).To(Succeed())

			_, _, mkdirSpec, _ := fakeOCIRuntime.ExecArgsForCall(0)
			_, _, tarSpec, _ := fakeOCIRuntime.ExecArgsForCall(1)
			Expect(mkdirSpec.User).To(Equal("root"))
			Expect(tarSpec.User).To(Equal("root"))
		})

		It("rejects an empty path without executing anything", func() {
			Expect(streamer.StreamIn(logger, "handle", garden.StreamInSpec{})).To(MatchError("stream-in: path must not be empty"))
			Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(0))
		})

		It("fails without running tar when mkdir cannot be executed", func() {
			fakeOCIRuntime.ExecReturnsOnCall(0, nil, errors.New("no-exec"))
			Expect(streamer.StreamIn(logger, "handle", garden.StreamInSpec{Path: "/dest"})).To(MatchError("stream-in: mkdir: exec: no-exec"))
			Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(1))
		})

		It("reports a failing tar with its exit code and stderr", func() {
			tar := new(gardenfakes.FakeProcess)
			tar.WaitReturns(2, nil)
			fakeOCIRuntime.ExecStub = func(_ lager.Logger, _ string, spec garden.ProcessSpec, pio garden.ProcessIO) (garden.Process, error) {
				if spec.Path == "/bin/tar" {
					_, _ = pio.Stderr.Write([]byte("tar: bad archive\n"))
					return tar, nil
				}
				return new(gardenfakes.FakeProcess), nil
			}

			Expect(streamer.StreamIn(logger, "handle", garden.StreamInSpec{Path: "/dest"})).To(MatchError("stream-in: tar: exited 2: tar: bad archive"))
		})

		It("keeps only a bounded amount of stderr", func() {
			tar := new(gardenfakes.FakeProcess)
			tar.WaitReturns(1, nil)
			fakeOCIRuntime.ExecStub = func(_ lager.Logger, _ string, spec garden.ProcessSpec, pio garden.ProcessIO) (garden.Process, error) {
				if spec.Path == "/bin/tar" {
					n, err := pio.Stderr.Write([]byte(strings.Repeat("e", 10000)))
					Expect(err).NotTo(HaveOccurred())
					Expect(n).To(Equal(10000))
					return tar, nil
				}
				return new(gardenfakes.FakeProcess), nil
			}

			err := streamer.StreamIn(logger, "handle", garden.StreamInSpec{Path: "/dest"})
			Expect(err).To(HaveOccurred())
			Expect(strings.Count(err.Error(), "e")).To(BeNumerically("<=", 4096+10))
		})

		It("reports a wait failure", func() {
			failing := new(gardenfakes.FakeProcess)
			failing.WaitReturns(0, errors.New("lost"))
			fakeOCIRuntime.ExecReturns(failing, nil)

			Expect(streamer.StreamIn(logger, "handle", garden.StreamInSpec{Path: "/dest"})).To(MatchError("stream-in: mkdir: wait: lost"))
		})
	})

	Describe("StreamOut", func() {
		var tar *gardenfakes.FakeProcess

		BeforeEach(func() {
			tar = new(gardenfakes.FakeProcess)
			fakeOCIRuntime.ExecStub = func(_ lager.Logger, _ string, _ garden.ProcessSpec, pio garden.ProcessIO) (garden.Process, error) {
				tar.WaitStub = func() (int, error) {
					_, _ = pio.Stdout.Write([]byte("archive-bytes"))
					return 0, nil
				}
				return tar, nil
			}
		})

		It("archives the named entry from its parent directory", func() {
			stream, err := streamer.StreamOut(logger, "handle", garden.StreamOutSpec{Path: "/a/b", User: "vcap"})
			Expect(err).NotTo(HaveOccurred())
			Expect(io.ReadAll(stream)).To(Equal([]byte("archive-bytes")))

			_, handle, spec, _ := fakeOCIRuntime.ExecArgsForCall(0)
			Expect(handle).To(Equal("handle"))
			Expect(spec.Path).To(Equal("/bin/tar"))
			Expect(spec.Args).To(Equal([]string{"-cf", "-", "-C", "/a", "b"}))
			Expect(spec.User).To(Equal("vcap"))
		})

		It("archives a directory's contents when the path ends in a slash", func() {
			stream, err := streamer.StreamOut(logger, "handle", garden.StreamOutSpec{Path: "/a/b/"})
			Expect(err).NotTo(HaveOccurred())
			Expect(io.ReadAll(stream)).To(Equal([]byte("archive-bytes")))

			_, _, spec, _ := fakeOCIRuntime.ExecArgsForCall(0)
			Expect(spec.Args).To(Equal([]string{"-cf", "-", "-C", "/a/b/", "."}))
			Expect(spec.User).To(Equal("root"))
		})

		It("surfaces a failing tar as a read error instead of a clean end of stream", func() {
			fakeOCIRuntime.ExecStub = func(_ lager.Logger, _ string, _ garden.ProcessSpec, pio garden.ProcessIO) (garden.Process, error) {
				tar.WaitStub = func() (int, error) {
					_, _ = pio.Stdout.Write([]byte("partial"))
					_, _ = pio.Stderr.Write([]byte("tar: /a/b: Cannot stat"))
					return 2, nil
				}
				return tar, nil
			}

			stream, err := streamer.StreamOut(logger, "handle", garden.StreamOutSpec{Path: "/a/b"})
			Expect(err).NotTo(HaveOccurred())

			data, err := io.ReadAll(stream)
			Expect(data).To(Equal([]byte("partial")))
			Expect(err).To(MatchError("stream-out: tar: exited 2: tar: /a/b: Cannot stat"))
		})

		It("surfaces a wait failure as a read error", func() {
			tar.WaitReturns(0, errors.New("lost"))
			fakeOCIRuntime.ExecReturns(tar, nil)
			fakeOCIRuntime.ExecStub = nil

			stream, err := streamer.StreamOut(logger, "handle", garden.StreamOutSpec{Path: "/a/b"})
			Expect(err).NotTo(HaveOccurred())

			_, err = io.ReadAll(stream)
			Expect(err).To(MatchError("stream-out: tar: wait: lost"))
		})

		It("returns no stream when tar cannot be executed", func() {
			fakeOCIRuntime.ExecStub = nil
			fakeOCIRuntime.ExecReturns(nil, errors.New("no-exec"))

			stream, err := streamer.StreamOut(logger, "handle", garden.StreamOutSpec{Path: "/a/b"})
			Expect(stream).To(BeNil())
			Expect(err).To(MatchError("stream-out: exec tar: no-exec"))
		})

		It("rejects an empty path without executing anything", func() {
			stream, err := streamer.StreamOut(logger, "handle", garden.StreamOutSpec{})
			Expect(stream).To(BeNil())
			Expect(err).To(MatchError("stream-out: path must not be empty"))
			Expect(fakeOCIRuntime.ExecCallCount()).To(Equal(0))
		})
	})
})
