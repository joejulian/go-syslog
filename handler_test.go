package syslog

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/joejulian/go-syslog/v2/format"
)

var _ = Describe("ChannelHandler", func() {
	It("writes log parts to the provided channel", func() {
		logPart := format.LogParts{"tag": "foo"}

		channel := make(LogPartsChannel, 1)
		handler := NewChannelHandler(channel)
		handler.Handle(logPart, 10, nil)

		fromChan := <-channel
		Expect(fromChan["tag"]).To(Equal(logPart["tag"]))
	})
})
