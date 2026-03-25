package rfc3164

import (
	"bytes"
	"testing"
	"time"

	"github.com/joejulian/go-syslog/v2/internal/syslogparser"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	// XXX : corresponds to the length of the last tried timestamp format
	// XXX : Jan  2 15:04:05
	lastTriedTimestampLen = 15
)

func testParser_Valid() {
	buff := []byte("<34>Oct 11 22:14:15 mymachine very.large.syslog.message.tag: 'su root' failed for lonvick on /dev/pts/8")

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	Expect(p).To(Equal(expectedP))

	err := p.Parse()
	Expect(err).To(BeNil())

	now := time.Now()

	obtained := p.Dump()
	expected := syslogparser.LogParts{
		"timestamp": time.Date(now.Year(), time.October, 11, 22, 14, 15, 0, time.UTC),
		"hostname":  "mymachine",
		"tag":       "very.large.syslog.message.tag",
		"content":   "'su root' failed for lonvick on /dev/pts/8",
		"priority":  34,
		"facility":  4,
		"severity":  2,
	}

	Expect(obtained).To(Equal(expected))
}

func testParser_ValidNoTag() {
	buff := []byte("<34>Oct 11 22:14:15 mymachine singleword")

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	Expect(p).To(Equal(expectedP))

	err := p.Parse()
	Expect(err).To(BeNil())

	now := time.Now()

	obtained := p.Dump()
	expected := syslogparser.LogParts{
		"timestamp": time.Date(now.Year(), time.October, 11, 22, 14, 15, 0, time.UTC),
		"hostname":  "mymachine",
		"tag":       "",
		"content":   "singleword",
		"priority":  34,
		"facility":  4,
		"severity":  2,
	}

	Expect(obtained).To(Equal(expected))
}

// RFC 3164 section 4.3.2
func testParser_NoTimestamp() {
	buff := []byte("<14>INFO     leaving (1) step postscripts")

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	Expect(p).To(Equal(expectedP))

	err := p.Parse()
	Expect(err).To(BeNil())

	now := time.Now()

	obtained := p.Dump()

	obtainedTime := obtained["timestamp"].(time.Time)
	assertTimeIsCloseToNow(obtainedTime)

	obtained["timestamp"] = now // XXX: Need to mock out time to test this fully
	expected := syslogparser.LogParts{
		"timestamp":          now,
		"timestamp_inferred": true,
		"hostname":           "",
		"tag":                "",
		"content":            "INFO     leaving (1) step postscripts",
		"priority":           14,
		"facility":           1,
		"severity":           6,
	}

	Expect(obtained).To(Equal(expected))
}

// RFC 3164 section 4.3.3
func testParser_NoPriority() {
	buff := []byte("Oct 11 22:14:15 Testing no priority")

	p := NewParser(buff)
	expectedP := &Parser{
		buff:     buff,
		cursor:   0,
		l:        len(buff),
		location: time.UTC,
	}

	Expect(p).To(Equal(expectedP))

	err := p.Parse()
	Expect(err).To(BeNil())

	now := time.Now()

	obtained := p.Dump()
	obtainedTime := obtained["timestamp"].(time.Time)
	assertTimeIsCloseToNow(obtainedTime)

	obtained["timestamp"] = now // XXX: Need to mock out time to test this fully
	expected := syslogparser.LogParts{
		"timestamp":          now,
		"timestamp_inferred": true,
		"hostname":           "",
		"tag":                "",
		"content":            "Oct 11 22:14:15 Testing no priority",
		"priority":           13,
		"priority_inferred":  true,
		"facility":           1,
		"severity":           5,
	}

	Expect(obtained).To(Equal(expected))
}

func testParseHeader_Valid() {
	buff := []byte("Oct 11 22:14:15 mymachine ")
	now := time.Now()
	hdr := header{
		timestamp: time.Date(now.Year(), time.October, 11, 22, 14, 15, 0, time.UTC),
		hostname:  "mymachine",
	}

	assertRfc3164Header(hdr, buff, 25, nil)

	// expected header for next two tests
	hdr = header{
		timestamp: time.Date(now.Year(), time.October, 1, 22, 14, 15, 0, time.UTC),
		hostname:  "mymachine",
	}
	// day with leading zero
	buff = []byte("Oct 01 22:14:15 mymachine ")
	assertRfc3164Header(hdr, buff, 25, nil)
	// day with leading space
	buff = []byte("Oct  1 22:14:15 mymachine ")
	assertRfc3164Header(hdr, buff, 25, nil)

}

func testParseHeader_RFC3339Timestamp() {
	buff := []byte("2018-01-12T22:14:15+00:00 mymachine app[101]: msg")
	hdr := header{
		timestamp: time.Date(2018, time.January, 12, 22, 14, 15, 0, time.UTC),
		hostname:  "mymachine",
	}
	assertRfc3164Header(hdr, buff, 35, nil)
}

func testParser_ValidRFC3339Timestamp() {
	buff := []byte("<34>2018-01-12T22:14:15+00:00 mymachine app[101]: msg")
	p := NewParser(buff)
	err := p.Parse()
	Expect(err).To(BeNil())
	obtained := p.Dump()
	expected := syslogparser.LogParts{
		"timestamp": time.Date(2018, time.January, 12, 22, 14, 15, 0, time.UTC),
		"hostname":  "mymachine",
		"tag":       "app",
		"content":   "msg",
		"priority":  34,
		"facility":  4,
		"severity":  2,
	}
	Expect(obtained).To(Equal(expected))
}

func testParseHeader_InvalidTimestamp() {
	buff := []byte("Oct 34 32:72:82 mymachine ")
	hdr := header{}

	assertRfc3164Header(hdr, buff, lastTriedTimestampLen+1, syslogparser.ErrTimestampUnknownFormat)
}

func testParsemessage_Valid() {
	content := "foo bar baz blah quux"
	buff := []byte("sometag[123]: " + content)
	hdr := rfc3164message{
		tag:     "sometag",
		content: content,
	}

	assertRfc3164message(hdr, buff, len(buff), syslogparser.ErrEOL)
}

func testParseTimestamp_Invalid() {
	buff := []byte("Oct 34 32:72:82")
	ts := new(time.Time)

	assertTimestamp(*ts, buff, lastTriedTimestampLen, syslogparser.ErrTimestampUnknownFormat)
}

func testParseTimestamp_TrailingSpace() {
	// XXX : no year specified. Assumed current year
	// XXX : no timezone specified. Assume UTC
	buff := []byte("Oct 11 22:14:15 ")

	now := time.Now()
	ts := time.Date(now.Year(), time.October, 11, 22, 14, 15, 0, time.UTC)

	assertTimestamp(ts, buff, len(buff), nil)
}

func testParseTimestamp_OneDigitForMonths() {
	// XXX : no year specified. Assumed current year
	// XXX : no timezone specified. Assume UTC
	buff := []byte("Oct  1 22:14:15")

	now := time.Now()
	ts := time.Date(now.Year(), time.October, 1, 22, 14, 15, 0, time.UTC)

	assertTimestamp(ts, buff, len(buff), nil)
}

func testParseTimestamp_Valid() {
	// XXX : no year specified. Assumed current year
	// XXX : no timezone specified. Assume UTC
	buff := []byte("Oct 11 22:14:15")

	now := time.Now()
	ts := time.Date(now.Year(), time.October, 11, 22, 14, 15, 0, time.UTC)

	assertTimestamp(ts, buff, len(buff), nil)
}

func testParseTag_Pid() {
	buff := []byte("apache2[10]:")
	tag := "apache2"

	assertTag(tag, buff, len(buff), nil)
}

func testParseTag_NoPid() {
	buff := []byte("apache2:")
	tag := "apache2"

	assertTag(tag, buff, len(buff), nil)
}

func testParseTag_TrailingSpace() {
	buff := []byte("apache2: ")
	tag := "apache2"

	assertTag(tag, buff, len(buff), nil)
}

func testParseTag_NoTag() {
	buff := []byte("apache2")
	tag := ""

	assertTag(tag, buff, 0, nil)
}

func testParseContent_Valid() {
	buff := []byte(" foo bar baz quux ")
	content := string(bytes.Trim(buff, " "))

	p := NewParser(buff)
	obtained, err := p.parseContent()
	Expect(err).To(Equal(syslogparser.ErrEOL))
	Expect(obtained).To(Equal(content))
	Expect(p.cursor).To(Equal(len(content)))
}

func BenchmarkParseTimestamp(b *testing.B) {
	buff := []byte("Oct 11 22:14:15")

	p := NewParser(buff)

	for i := 0; i < b.N; i++ {
		_, err := p.parseTimestamp()
		if err != nil {
			panic(err)
		}

		p.cursor = 0
	}
}

func BenchmarkParseHostname(b *testing.B) {
	buff := []byte("gimli.local")

	p := NewParser(buff)

	for i := 0; i < b.N; i++ {
		_, err := p.parseHostname()
		if err != nil {
			panic(err)
		}

		p.cursor = 0
	}
}

func BenchmarkParseTag(b *testing.B) {
	buff := []byte("apache2[10]:")

	p := NewParser(buff)

	for i := 0; i < b.N; i++ {
		_, err := p.parseTag()
		if err != nil {
			panic(err)
		}

		p.cursor = 0
	}
}

func BenchmarkParseHeader(b *testing.B) {
	buff := []byte("Oct 11 22:14:15 mymachine ")

	p := NewParser(buff)

	for i := 0; i < b.N; i++ {
		_, err := p.parseHeader()
		if err != nil {
			panic(err)
		}

		p.cursor = 0
	}
}

func BenchmarkParsemessage(b *testing.B) {
	buff := []byte("sometag[123]: foo bar baz blah quux")

	p := NewParser(buff)

	for i := 0; i < b.N; i++ {
		_, err := p.parsemessage()
		if err != syslogparser.ErrEOL {
			panic(err)
		}

		p.cursor = 0
	}
}

func assertTimestamp(ts time.Time, b []byte, expC int, e error) {
	p := NewParser(b)
	obtained, err := p.parseTimestamp()
	Expect(obtained).To(Equal(ts))
	Expect(p.cursor).To(Equal(expC))
	expectError(err, e)
}

func assertTag(t string, b []byte, expC int, e error) {
	p := NewParser(b)
	obtained, err := p.parseTag()
	Expect(obtained).To(Equal(t))
	Expect(p.cursor).To(Equal(expC))
	expectError(err, e)
}

func assertRfc3164Header(hdr header, b []byte, expC int, e error) {
	p := NewParser(b)
	obtained, err := p.parseHeader()
	expectError(err, e)
	Expect(obtained).To(Equal(hdr))
	Expect(p.cursor).To(Equal(expC))
}

func assertRfc3164message(msg rfc3164message, b []byte, expC int, e error) {
	p := NewParser(b)
	obtained, err := p.parsemessage()
	expectError(err, e)
	Expect(obtained).To(Equal(msg))
	Expect(p.cursor).To(Equal(expC))
}

func expectError(obtained error, expected error) {
	if expected == nil {
		Expect(obtained).To(BeNil())
		return
	}
	Expect(obtained).To(Equal(expected))
}

func assertTimeIsCloseToNow(obtainedTime time.Time) {
	now := time.Now()
	timeStart := now.Add(-(time.Second * 5))
	timeEnd := now.Add(time.Second)
	Expect(obtainedTime.After(timeStart)).To(Equal(true))
	Expect(obtainedTime.Before(timeEnd)).To(Equal(true))
}

var _ = Describe("RFC3164 parser", func() {
	It("parser valid", testParser_Valid)
	It("parser valid no tag", testParser_ValidNoTag)
	It("parser no timestamp", testParser_NoTimestamp)
	It("parser no priority", testParser_NoPriority)
	It("parse header valid", testParseHeader_Valid)
	It("parse header rfc3339 timestamp", testParseHeader_RFC3339Timestamp)
	It("parser valid rfc3339 timestamp", testParser_ValidRFC3339Timestamp)
	It("parse header invalid timestamp", testParseHeader_InvalidTimestamp)
	It("parsemessage valid", testParsemessage_Valid)
	It("parse timestamp invalid", testParseTimestamp_Invalid)
	It("parse timestamp trailing space", testParseTimestamp_TrailingSpace)
	It("parse timestamp one digit for months", testParseTimestamp_OneDigitForMonths)
	It("parse timestamp valid", testParseTimestamp_Valid)
	It("parse tag pid", testParseTag_Pid)
	It("parse tag no pid", testParseTag_NoPid)
	It("parse tag trailing space", testParseTag_TrailingSpace)
	It("parse tag no tag", testParseTag_NoTag)
	It("parse content valid", testParseContent_Valid)
})
