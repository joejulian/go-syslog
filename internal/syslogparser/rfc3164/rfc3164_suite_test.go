package rfc3164

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestRfc3164(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "RFC3164 Parser Suite")
}
