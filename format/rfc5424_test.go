package format

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RFC5424", func() {
	It("does not provide a split function", func() {
		f := RFC5424{}
		Expect(f.GetSplitFunc()).To(BeNil())
	})
})
