package syslogparser

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func testParsePriority_Empty() {
	pri := newPriority(0)
	buff := []byte("")
	start := 0

	assertPriority(pri, buff, start, start, ErrPriorityEmpty)
}

func testParsePriority_NoStart() {
	pri := newPriority(0)
	buff := []byte("7>")
	start := 0

	assertPriority(pri, buff, start, start, ErrPriorityNoStart)
}

func testParsePriority_NoEnd() {
	pri := newPriority(0)
	buff := []byte("<77")
	start := 0

	assertPriority(pri, buff, start, start, ErrPriorityNoEnd)
}

func testParsePriority_TooShort() {
	pri := newPriority(0)
	buff := []byte("<>")
	start := 0

	assertPriority(pri, buff, start, start, ErrPriorityTooShort)
}

func testParsePriority_TooLong() {
	pri := newPriority(0)
	buff := []byte("<1233>")
	start := 0

	assertPriority(pri, buff, start, start, ErrPriorityTooLong)
}

func testParsePriority_NoDigits() {
	pri := newPriority(0)
	buff := []byte("<7a8>")
	start := 0

	assertPriority(pri, buff, start, start, ErrPriorityNonDigit)
}

func testParsePriority_Ok() {
	pri := newPriority(190)
	buff := []byte("<190>")
	start := 0

	assertPriority(pri, buff, start, start+5, nil)
}

func testNewPriority() {
	obtained := newPriority(165)

	expected := Priority{
		P: 165,
		F: Facility{Value: 20},
		S: Severity{Value: 5},
	}

	Expect(obtained).To(Equal(expected))
}

func testParseVersion_NotFound() {
	buff := []byte("<123>")
	start := 5

	assertVersion(NO_VERSION, buff, start, start, ErrVersionNotFound)
}

func testParseVersion_NonDigit() {
	buff := []byte("<123>a")
	start := 5

	assertVersion(NO_VERSION, buff, start, start+1, nil)
}

func testParseVersion_Ok() {
	buff := []byte("<123>1")
	start := 5

	assertVersion(1, buff, start, start+1, nil)
}

func testParseHostname_Invalid() {
	// XXX : no year specified. Assumed current year
	// XXX : no timezone specified. Assume UTC
	buff := []byte("foo name")
	start := 0
	hostname := "foo"

	assertHostname(hostname, buff, start, 3, nil)
}

func testParseHostname_Valid() {
	// XXX : no year specified. Assumed current year
	// XXX : no timezone specified. Assume UTC
	hostname := "ubuntu11.somehost.com"
	buff := []byte(hostname + " ")
	start := 0

	assertHostname(hostname, buff, start, len(hostname), nil)
}

func BenchmarkParsePriority(b *testing.B) {
	buff := []byte("<190>")
	var start int
	l := len(buff)

	for i := 0; i < b.N; i++ {
		start = 0
		_, err := ParsePriority(buff, &start, l)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkParseVersion(b *testing.B) {
	buff := []byte("<123>1")
	start := 5
	l := len(buff)

	for i := 0; i < b.N; i++ {
		start = 0
		_, err := ParseVersion(buff, &start, l)
		if err != nil {
			panic(err)
		}
	}
}

func assertPriority(p Priority, b []byte, cursor int, expC int, e error) {
	obtained, err := ParsePriority(b, &cursor, len(b))
	Expect(obtained).To(Equal(p))
	Expect(cursor).To(Equal(expC))
	expectError(err, e)
}

func assertVersion(version int, b []byte, cursor int, expC int, e error) {
	obtained, err := ParseVersion(b, &cursor, len(b))
	Expect(obtained).To(Equal(version))
	Expect(cursor).To(Equal(expC))
	expectError(err, e)
}

func assertHostname(h string, b []byte, cursor int, expC int, e error) {
	obtained, err := ParseHostname(b, &cursor, len(b))
	Expect(obtained).To(Equal(h))
	Expect(cursor).To(Equal(expC))
	expectError(err, e)
}

func expectError(obtained error, expected error) {
	if expected == nil {
		Expect(obtained).To(BeNil())
		return
	}
	Expect(obtained).To(Equal(expected))
}

var _ = Describe("Common parser helpers", func() {
	It("parse priority empty", testParsePriority_Empty)
	It("parse priority no start", testParsePriority_NoStart)
	It("parse priority no end", testParsePriority_NoEnd)
	It("parse priority too short", testParsePriority_TooShort)
	It("parse priority too long", testParsePriority_TooLong)
	It("parse priority no digits", testParsePriority_NoDigits)
	It("parse priority ok", testParsePriority_Ok)
	It("new priority", testNewPriority)
	It("parse version not found", testParseVersion_NotFound)
	It("parse version non digit", testParseVersion_NonDigit)
	It("parse version ok", testParseVersion_Ok)
	It("parse hostname invalid", testParseHostname_Invalid)
	It("parse hostname valid", testParseHostname_Valid)
})
