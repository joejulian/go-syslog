package rfc5424

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestRfc5424(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "RFC5424 Parser Suite")
}
