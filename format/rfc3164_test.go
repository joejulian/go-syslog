package format

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RFC3164", func() {
	It("does not provide a split function", func() {
		f := RFC3164{}
		Expect(f.GetSplitFunc()).To(BeNil())
	})

	It("parses a typical message", func() {
		f := RFC3164{}

		line := `<13>May  1 20:51:40 myhostname myprogram: ciao`
		parser := f.GetParser([]byte(line))
		err := parser.Parse()
		Expect(err).NotTo(HaveOccurred())
		Expect(parser.Dump()["content"]).To(Equal("ciao"))
		Expect(parser.Dump()["hostname"]).To(Equal("myhostname"))
		Expect(parser.Dump()["tag"]).To(Equal("myprogram"))
	})

	It("parses a typical message with a pid", func() {
		f := RFC3164{}

		line := `<13>May  1 20:51:40 myhostname myprogram[42]: ciao`
		parser := f.GetParser([]byte(line))
		err := parser.Parse()
		Expect(err).NotTo(HaveOccurred())
		Expect(parser.Dump()["content"]).To(Equal("ciao"))
		Expect(parser.Dump()["hostname"]).To(Equal("myhostname"))
		Expect(parser.Dump()["tag"]).To(Equal("myprogram"))
	})

	It("parses the GNU syslog variant without a hostname", func() {
		f := RFC3164{}

		line := `<13>May  1 20:51:40 myprogram: ciao`
		parser := f.GetParser([]byte(line))
		err := parser.Parse()
		Expect(err).NotTo(HaveOccurred())
		Expect(parser.Dump()["content"]).To(Equal("ciao"))
		Expect(parser.Dump()["tag"]).To(Equal("myprogram"))
	})

	It("parses the journald variant without a hostname", func() {
		f := RFC3164{}

		line := `<78>May  1 20:51:02 myprog[153]: blah`
		parser := f.GetParser([]byte(line))
		err := parser.Parse()
		Expect(err).NotTo(HaveOccurred())
		Expect(parser.Dump()["content"]).To(Equal("blah"))
		Expect(parser.Dump()["tag"]).To(Equal("myprog"))
	})
})
