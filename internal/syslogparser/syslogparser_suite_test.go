package syslogparser

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSyslogparser(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Syslogparser Suite")
}
