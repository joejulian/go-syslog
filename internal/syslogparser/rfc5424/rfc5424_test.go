package rfc5424

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/joejulian/go-syslog/v2/internal/syslogparser"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func testParser_Valid() {
	fixtures := []string{
		// no STRUCTURED-DATA
		"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8",
		"<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.",
		"<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 012345678901234567890123456789012345678901234567 8710 - - %% It's time to make the do-nuts.",
		// with STRUCTURED-DATA
		`<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] An application event log entry...`,
		// STRUCTURED-DATA Only
		`<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource= "Application" eventID="1011"][examplePriority@32473 class="high"]`,
		// STRUCTURED-DATA Only
		`<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 `,
	}

	tmpTs, err := time.Parse("-07:00", "-07:00")
	Expect(err).To(BeNil())

	expected := []syslogparser.LogParts{
		syslogparser.LogParts{
			"priority":        34,
			"facility":        4,
			"severity":        2,
			"version":         1,
			"timestamp":       time.Date(2003, time.October, 11, 22, 14, 15, 3*10e5, time.UTC),
			"hostname":        "mymachine.example.com",
			"app_name":        "su",
			"proc_id":         "-",
			"msg_id":          "ID47",
			"structured_data": "-",
			"message":         "'su root' failed for lonvick on /dev/pts/8",
		},
		syslogparser.LogParts{
			"priority":        165,
			"facility":        20,
			"severity":        5,
			"version":         1,
			"timestamp":       time.Date(2003, time.August, 24, 5, 14, 15, 3*10e2, tmpTs.Location()),
			"hostname":        "192.0.2.1",
			"app_name":        "myproc",
			"proc_id":         "8710",
			"msg_id":          "-",
			"structured_data": "-",
			"message":         "%% It's time to make the do-nuts.",
		},
		syslogparser.LogParts{
			"priority":        165,
			"facility":        20,
			"severity":        5,
			"version":         1,
			"timestamp":       time.Date(2003, time.August, 24, 5, 14, 15, 3*10e2, tmpTs.Location()),
			"hostname":        "192.0.2.1",
			"app_name":        "012345678901234567890123456789012345678901234567",
			"proc_id":         "8710",
			"msg_id":          "-",
			"structured_data": "-",
			"message":         "%% It's time to make the do-nuts.",
		},
		syslogparser.LogParts{
			"priority":        165,
			"facility":        20,
			"severity":        5,
			"version":         1,
			"timestamp":       time.Date(2003, time.October, 11, 22, 14, 15, 3*10e5, time.UTC),
			"hostname":        "mymachine.example.com",
			"app_name":        "evntslog",
			"proc_id":         "-",
			"msg_id":          "ID47",
			"structured_data": `[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]`,
			"message":         "An application event log entry...",
		},
		syslogparser.LogParts{
			"priority":        165,
			"facility":        20,
			"severity":        5,
			"version":         1,
			"timestamp":       time.Date(2003, time.October, 11, 22, 14, 15, 3*10e5, time.UTC),
			"hostname":        "mymachine.example.com",
			"app_name":        "evntslog",
			"proc_id":         "-",
			"msg_id":          "ID47",
			"structured_data": `[exampleSDID@32473 iut="3" eventSource= "Application" eventID="1011"][examplePriority@32473 class="high"]`,
			"message":         "",
		},
		syslogparser.LogParts{
			"priority":        165,
			"facility":        20,
			"severity":        5,
			"version":         1,
			"timestamp":       time.Date(2003, time.October, 11, 22, 14, 15, 3*10e5, time.UTC),
			"hostname":        "mymachine.example.com",
			"app_name":        "evntslog",
			"proc_id":         "-",
			"msg_id":          "ID47",
			"structured_data": "-",
			"message":         "",
		},
	}

	Expect(len(fixtures)).To(Equal(len(expected)))
	start := 0
	for i, buff := range fixtures {
		expectedP := &Parser{
			buff:   []byte(buff),
			cursor: start,
			l:      len(buff),
		}

		p := NewParser([]byte(buff))
		Expect(p).To(Equal(expectedP))

		err := p.Parse()
		Expect(err).To(BeNil())

		obtained := p.Dump()
		for k, v := range obtained {
			Expect(v).To(Equal(expected[i][k]))
		}
	}
}

func testParser_Truncated() {
	msg := "<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts."
	for i := range msg {
		p := NewParser([]byte(msg[:i]))
		_ = p.Parse()
	}
}

func testParseHeader_Valid() {
	ts := time.Date(2003, time.October, 11, 22, 14, 15, 3*10e5, time.UTC)
	tsString := "2003-10-11T22:14:15.003Z"
	hostname := "mymachine.example.com"
	appName := "su"
	procId := "123"
	msgId := "ID47"
	nilValue := string(NILVALUE)
	headerFmt := "<165>1 %s %s %s %s %s "

	fixtures := []string{
		// HEADER complete
		fmt.Sprintf(headerFmt, tsString, hostname, appName, procId, msgId),
		// TIMESTAMP as NILVALUE
		fmt.Sprintf(headerFmt, nilValue, hostname, appName, procId, msgId),
		// HOSTNAME as NILVALUE
		fmt.Sprintf(headerFmt, tsString, nilValue, appName, procId, msgId),
		// APP-NAME as NILVALUE
		fmt.Sprintf(headerFmt, tsString, hostname, nilValue, procId, msgId),
		// PROCID as NILVALUE
		fmt.Sprintf(headerFmt, tsString, hostname, appName, nilValue, msgId),
		// MSGID as NILVALUE
		fmt.Sprintf(headerFmt, tsString, hostname, appName, procId, nilValue),
	}

	pri := syslogparser.Priority{
		P: 165,
		F: syslogparser.Facility{Value: 20},
		S: syslogparser.Severity{Value: 5},
	}

	expected := []header{
		// HEADER complete
		header{
			priority:  pri,
			version:   1,
			timestamp: ts,
			hostname:  hostname,
			appName:   appName,
			procId:    procId,
			msgId:     msgId,
		},
		// TIMESTAMP as NILVALUE
		header{
			priority:  pri,
			version:   1,
			timestamp: *new(time.Time),
			hostname:  hostname,
			appName:   appName,
			procId:    procId,
			msgId:     msgId,
		},
		// HOSTNAME as NILVALUE
		header{
			priority:  pri,
			version:   1,
			timestamp: ts,
			hostname:  nilValue,
			appName:   appName,
			procId:    procId,
			msgId:     msgId,
		},
		// APP-NAME as NILVALUE
		header{
			priority:  pri,
			version:   1,
			timestamp: ts,
			hostname:  hostname,
			appName:   nilValue,
			procId:    procId,
			msgId:     msgId,
		},
		// PROCID as NILVALUE
		header{
			priority:  pri,
			version:   1,
			timestamp: ts,
			hostname:  hostname,
			appName:   appName,
			procId:    nilValue,
			msgId:     msgId,
		},
		// MSGID as NILVALUE
		header{
			priority:  pri,
			version:   1,
			timestamp: ts,
			hostname:  hostname,
			appName:   appName,
			procId:    procId,
			msgId:     nilValue,
		},
	}

	for i, f := range fixtures {
		p := NewParser([]byte(f))
		obtained, err := p.parseHeader()
		Expect(err).To(BeNil())
		Expect(obtained).To(Equal(expected[i]))
		Expect(p.cursor).To(Equal(len(f)))
	}
}

func testParseHeader_InvalidProcID() {
	procID := strings.Repeat("1", 129)
	buff := []byte(fmt.Sprintf("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com su %s ID47 ", procID))

	p := NewParser(buff)
	_, err := p.parseHeader()

	Expect(err).To(Equal(ErrInvalidProcId))
}

func testParseHeader_InvalidMsgID() {
	msgID := strings.Repeat("1", 33)
	buff := []byte(fmt.Sprintf("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com su 123 %s ", msgID))

	p := NewParser(buff)
	_, err := p.parseHeader()

	Expect(err).To(Equal(ErrInvalidMsgId))
}

func testParseTimestamp_UTC() {
	buff := []byte("1985-04-12T23:20:50.52Z")
	ts := time.Date(1985, time.April, 12, 23, 20, 50, 52*10e6, time.UTC)

	assertTimestamp(ts, buff, 23, nil)
}

func testParseTimestamp_NumericTimezone() {
	tz := "-04:00"
	buff := []byte("1985-04-12T19:20:50.52" + tz)

	tmpTs, err := time.Parse("-07:00", tz)
	Expect(err).To(BeNil())

	ts := time.Date(1985, time.April, 12, 19, 20, 50, 52*10e6, tmpTs.Location())

	assertTimestamp(ts, buff, len(buff), nil)
}

func testParseTimestamp_MilliSeconds() {
	buff := []byte("2003-10-11T22:14:15.003Z")

	ts := time.Date(2003, time.October, 11, 22, 14, 15, 3*10e5, time.UTC)

	assertTimestamp(ts, buff, len(buff), nil)
}

func testParseTimestamp_MicroSeconds() {
	tz := "-07:00"
	buff := []byte("2003-08-24T05:14:15.000003" + tz)

	tmpTs, err := time.Parse("-07:00", tz)
	Expect(err).To(BeNil())

	ts := time.Date(2003, time.August, 24, 5, 14, 15, 3*10e2, tmpTs.Location())

	assertTimestamp(ts, buff, len(buff), nil)
}

func testParseTimestamp_NanoSeconds() {
	buff := []byte("2003-08-24T05:14:15.000000003-07:00")
	ts := new(time.Time)

	assertTimestamp(*ts, buff, 26, syslogparser.ErrTimestampUnknownFormat)
}

func testParseTimestamp_NilValue() {
	buff := []byte("-")
	ts := new(time.Time)

	assertTimestamp(*ts, buff, 1, nil)
}

func testParseTimestamp_Empty() {
	buff := []byte("")
	ts := new(time.Time)

	assertTimestamp(*ts, buff, 0, ErrInvalidTimeFormat)
}

func testFindNextSpace_NoSpace() {
	buff := []byte("aaaaaa")

	assertFindNextSpace(0, buff, syslogparser.ErrNoSpace)
}

func testFindNextSpace_SpaceFound() {
	buff := []byte("foo bar baz")

	assertFindNextSpace(4, buff, nil)
}

func testParseYear_Invalid() {
	buff := []byte("1a2b")
	expected := 0

	assertParseYear(expected, buff, 4, ErrYearInvalid)
}

func testParseYear_TooShort() {
	buff := []byte("123")
	expected := 0

	assertParseYear(expected, buff, 0, syslogparser.ErrEOL)
}

func testParseYear_Valid() {
	buff := []byte("2013")
	expected := 2013

	assertParseYear(expected, buff, 4, nil)
}

func testParseMonth_InvalidString() {
	buff := []byte("ab")
	expected := 0

	assertParseMonth(expected, buff, 2, ErrMonthInvalid)
}

func testParseMonth_InvalidRange() {
	buff := []byte("00")
	expected := 0

	assertParseMonth(expected, buff, 2, ErrMonthInvalid)

	// ----

	buff = []byte("13")

	assertParseMonth(expected, buff, 2, ErrMonthInvalid)
}

func testParseMonth_TooShort() {
	buff := []byte("1")
	expected := 0

	assertParseMonth(expected, buff, 0, syslogparser.ErrEOL)
}

func testParseMonth_Valid() {
	buff := []byte("02")
	expected := 2

	assertParseMonth(expected, buff, 2, nil)
}

func testParseDay_InvalidString() {
	buff := []byte("ab")
	expected := 0

	assertParseDay(expected, buff, 2, ErrDayInvalid)
}

func testParseDay_TooShort() {
	buff := []byte("1")
	expected := 0

	assertParseDay(expected, buff, 0, syslogparser.ErrEOL)
}

func testParseDay_InvalidRange() {
	buff := []byte("00")
	expected := 0

	assertParseDay(expected, buff, 2, ErrDayInvalid)

	// ----

	buff = []byte("32")

	assertParseDay(expected, buff, 2, ErrDayInvalid)
}

func testParseDay_Valid() {
	buff := []byte("02")
	expected := 2

	assertParseDay(expected, buff, 2, nil)
}

func testParseFullDate_Invalid() {
	buff := []byte("2013+10-28")
	fd := fullDate{}

	assertParseFullDate(fd, buff, 4, syslogparser.ErrTimestampUnknownFormat)

	// ---

	buff = []byte("2013-10+28")
	assertParseFullDate(fd, buff, 7, syslogparser.ErrTimestampUnknownFormat)
}

func testParseFullDate_Valid() {
	buff := []byte("2013-10-28")
	fd := fullDate{
		year:  2013,
		month: 10,
		day:   28,
	}

	assertParseFullDate(fd, buff, len(buff), nil)
}

func testParseHour_InvalidString() {
	buff := []byte("azer")
	expected := 0

	assertParseHour(expected, buff, 2, ErrHourInvalid)
}

func testParseHour_TooShort() {
	buff := []byte("1")
	expected := 0

	assertParseHour(expected, buff, 0, syslogparser.ErrEOL)
}

func testParseHour_InvalidRange() {
	buff := []byte("-1")
	expected := 0

	assertParseHour(expected, buff, 2, ErrHourInvalid)

	// ----

	buff = []byte("24")

	assertParseHour(expected, buff, 2, ErrHourInvalid)
}

func testParseHour_Valid() {
	buff := []byte("12")
	expected := 12

	assertParseHour(expected, buff, 2, nil)
}

func testParseMinute_InvalidString() {
	buff := []byte("azer")
	expected := 0

	assertParseMinute(expected, buff, 2, ErrMinuteInvalid)
}

func testParseMinute_TooShort() {
	buff := []byte("1")
	expected := 0

	assertParseMinute(expected, buff, 0, syslogparser.ErrEOL)
}

func testParseMinute_InvalidRange() {
	buff := []byte("-1")
	expected := 0

	assertParseMinute(expected, buff, 2, ErrMinuteInvalid)

	// ----

	buff = []byte("60")

	assertParseMinute(expected, buff, 2, ErrMinuteInvalid)
}

func testParseMinute_Valid() {
	buff := []byte("12")
	expected := 12

	assertParseMinute(expected, buff, 2, nil)
}

func testParseSecond_InvalidString() {
	buff := []byte("azer")
	expected := 0

	assertParseSecond(expected, buff, 2, ErrSecondInvalid)
}

func testParseSecond_TooShort() {
	buff := []byte("1")
	expected := 0

	assertParseSecond(expected, buff, 0, syslogparser.ErrEOL)
}

func testParseSecond_InvalidRange() {
	buff := []byte("-1")
	expected := 0

	assertParseSecond(expected, buff, 2, ErrSecondInvalid)

	// ----

	buff = []byte("60")

	assertParseSecond(expected, buff, 2, ErrSecondInvalid)
}

func testParseSecond_Valid() {
	buff := []byte("12")
	expected := 12

	assertParseSecond(expected, buff, 2, nil)
}

func testParseSecFrac_InvalidString() {
	buff := []byte("azerty")
	expected := 0.0

	assertParseSecFrac(expected, buff, 0, ErrSecFracInvalid)
}

func testParseSecFrac_NanoSeconds() {
	buff := []byte("123456789")
	expected := 0.123456

	assertParseSecFrac(expected, buff, 6, nil)
}

func testParseSecFrac_Valid() {
	buff := []byte("0")

	expected := 0.0
	assertParseSecFrac(expected, buff, 1, nil)

	buff = []byte("52")
	expected = 0.52
	assertParseSecFrac(expected, buff, 2, nil)

	buff = []byte("003")
	expected = 0.003
	assertParseSecFrac(expected, buff, 3, nil)

	buff = []byte("000003")
	expected = 0.000003
	assertParseSecFrac(expected, buff, 6, nil)
}

func testParseNumericalTimeOffset_Valid() {
	buff := []byte("+02:00")
	cursor := 0
	l := len(buff)
	tmpTs, err := time.Parse("-07:00", string(buff))
	Expect(err).To(BeNil())

	obtained, err := parseNumericalTimeOffset(buff, &cursor, l)
	Expect(err).To(BeNil())

	expected := tmpTs.Location()
	Expect(obtained).To(Equal(expected))

	Expect(cursor).To(Equal(6))
}

func testParseTimeOffset_Valid() {
	buff := []byte("Z")
	cursor := 0
	l := len(buff)

	obtained, err := parseTimeOffset(buff, &cursor, l)
	Expect(err).To(BeNil())
	Expect(obtained).To(Equal(time.UTC))
	Expect(cursor).To(Equal(1))
}

func testGetHourMin_Valid() {
	buff := []byte("12:34")
	cursor := 0
	l := len(buff)

	expectedHour := 12
	expectedMinute := 34

	obtainedHour, obtainedMinute, err := getHourMinute(buff, &cursor, l)
	Expect(err).To(BeNil())
	Expect(obtainedHour).To(Equal(expectedHour))
	Expect(obtainedMinute).To(Equal(expectedMinute))

	Expect(cursor).To(Equal(l))
}

func testParsePartialTime_Valid() {
	buff := []byte("05:14:15.000003")
	cursor := 0
	l := len(buff)

	obtained, err := parsePartialTime(buff, &cursor, l)
	expected := partialTime{
		hour:    5,
		minute:  14,
		seconds: 15,
		secFrac: 0.000003,
	}

	Expect(err).To(BeNil())
	Expect(obtained).To(Equal(expected))
	Expect(cursor).To(Equal(l))
}

func testParseFullTime_Valid() {
	tz := "-02:00"
	buff := []byte("05:14:15.000003" + tz)
	cursor := 0
	l := len(buff)

	tmpTs, err := time.Parse("-07:00", string(tz))
	Expect(err).To(BeNil())

	obtainedFt, err := parseFullTime(buff, &cursor, l)
	expectedFt := fullTime{
		pt: partialTime{
			hour:    5,
			minute:  14,
			seconds: 15,
			secFrac: 0.000003,
		},
		loc: tmpTs.Location(),
	}

	Expect(err).To(BeNil())
	Expect(obtainedFt).To(Equal(expectedFt))
	Expect(cursor).To(Equal(21))
}

func testToNSec() {
	fixtures := []float64{
		0.52,
		0.003,
		0.000003,
	}

	expected := []int{
		520000000,
		3000000,
		3000,
	}

	Expect(len(fixtures)).To(Equal(len(expected)))
	for i, f := range fixtures {
		obtained, err := toNSec(f)
		Expect(err).To(BeNil())
		Expect(obtained).To(Equal(expected[i]))
	}
}

func testParseAppName_Valid() {
	buff := []byte("su ")
	appName := "su"

	assertParseAppName(appName, buff, 2, nil)
}

func testParseAppName_TooLong() {
	// > 48chars
	buff := []byte("suuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu ")
	appName := ""

	assertParseAppName(appName, buff, 48, ErrInvalidAppName)
}

func testParseProcId_Valid() {
	buff := []byte("123foo ")
	procId := "123foo"

	assertParseProcId(procId, buff, 6, nil)
}

func testParseProcId_TooLong() {
	// > 128chars
	buff := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab ")
	procId := ""

	assertParseProcId(procId, buff, 128, ErrInvalidProcId)
}

func testParseMsgId_Valid() {
	buff := []byte("123foo ")
	procId := "123foo"

	assertParseMsgId(procId, buff, 6, nil)
}

func testParseMsgId_TooLong() {
	// > 32chars
	buff := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ")
	procId := ""

	assertParseMsgId(procId, buff, 32, ErrInvalidMsgId)
}

func testParseStructuredData_NilValue() {
	// > 32chars
	buff := []byte("-")
	sdData := "-"

	assertParseSdName(sdData, buff, 1, nil)
}

func testParseStructuredData_SingleStructuredData() {
	sdData := `[exampleSDID@32473 iut="3" eventSource="Application"eventID="1011"]`
	buff := []byte(sdData)

	assertParseSdName(sdData, buff, len(buff), nil)
}

func testParseStructuredData_MultipleStructuredData() {
	sdData := `[exampleSDID@32473 iut="3" eventSource="Application"eventID="1011"][examplePriority@32473 class="high"]`
	buff := []byte(sdData)

	assertParseSdName(sdData, buff, len(buff), nil)
}

func testParseStructuredData_MultipleStructuredDataInvalid() {
	a := `[exampleSDID@32473 iut="3" eventSource="Application"eventID="1011"]`
	sdData := a + ` [examplePriority@32473 class="high"]`
	buff := []byte(sdData)

	assertParseSdName(a, buff, len(a), nil)
}

// -------------

func BenchmarkParseTimestamp(b *testing.B) {
	buff := []byte("2003-08-24T05:14:15.000003-07:00")

	p := NewParser(buff)

	for i := 0; i < b.N; i++ {
		_, err := p.parseTimestamp()
		if err != nil {
			panic(err)
		}

		p.cursor = 0
	}
}

func BenchmarkParseHeader(b *testing.B) {
	buff := []byte("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com su 123 ID47")

	p := NewParser(buff)

	for i := 0; i < b.N; i++ {
		_, err := p.parseHeader()
		if err != nil {
			panic(err)
		}

		p.cursor = 0
	}
}

// -------------

func assertTimestamp(ts time.Time, b []byte, expC int, e error) {
	p := NewParser(b)
	obtained, err := p.parseTimestamp()
	expectError(err, e)

	tFmt := time.RFC3339Nano
	Expect(obtained.Format(tFmt)).To(Equal(ts.Format(tFmt)))

	Expect(p.cursor).To(Equal(expC))
}

func assertFindNextSpace(expC int, b []byte, e error) {
	obtained, err := syslogparser.FindNextSpace(b, 0, len(b))
	Expect(obtained).To(Equal(expC))
	expectError(err, e)
}

func assertParseYear(year int, b []byte, expC int, e error) {
	cursor := 0
	obtained, err := parseYear(b, &cursor, len(b))
	Expect(obtained).To(Equal(year))
	expectError(err, e)
	Expect(cursor).To(Equal(expC))
}

func assertParseMonth(month int, b []byte, expC int, e error) {
	cursor := 0
	obtained, err := parseMonth(b, &cursor, len(b))
	Expect(obtained).To(Equal(month))
	expectError(err, e)
	Expect(cursor).To(Equal(expC))
}

func assertParseDay(day int, b []byte, expC int, e error) {
	cursor := 0
	obtained, err := parseDay(b, &cursor, len(b))
	Expect(obtained).To(Equal(day))
	expectError(err, e)
	Expect(cursor).To(Equal(expC))
}

func assertParseFullDate(fd fullDate, b []byte, expC int, e error) {
	cursor := 0
	obtained, err := parseFullDate(b, &cursor, len(b))
	expectError(err, e)
	Expect(obtained).To(Equal(fd))
	Expect(cursor).To(Equal(expC))
}

func assertParseHour(hour int, b []byte, expC int, e error) {
	cursor := 0
	obtained, err := parseHour(b, &cursor, len(b))
	Expect(obtained).To(Equal(hour))
	expectError(err, e)
	Expect(cursor).To(Equal(expC))
}

func assertParseMinute(minute int, b []byte, expC int, e error) {
	cursor := 0
	obtained, err := parseMinute(b, &cursor, len(b))
	Expect(obtained).To(Equal(minute))
	expectError(err, e)
	Expect(cursor).To(Equal(expC))
}

func assertParseSecond(second int, b []byte, expC int, e error) {
	cursor := 0
	obtained, err := parseSecond(b, &cursor, len(b))
	Expect(obtained).To(Equal(second))
	expectError(err, e)
	Expect(cursor).To(Equal(expC))
}

func assertParseSecFrac(secFrac float64, b []byte, expC int, e error) {
	cursor := 0
	obtained, err := parseSecFrac(b, &cursor, len(b))
	Expect(obtained).To(Equal(secFrac))
	expectError(err, e)
	Expect(cursor).To(Equal(expC))
}

func assertParseAppName(appName string, b []byte, expC int, e error) {
	p := NewParser(b)
	obtained, err := p.parseAppName()

	expectError(err, e)
	Expect(obtained).To(Equal(appName))
	Expect(p.cursor).To(Equal(expC))
}

func assertParseProcId(procId string, b []byte, expC int, e error) {
	p := NewParser(b)
	obtained, err := p.parseProcId()

	expectError(err, e)
	Expect(obtained).To(Equal(procId))
	Expect(p.cursor).To(Equal(expC))
}

func assertParseMsgId(msgId string, b []byte, expC int, e error) {
	p := NewParser(b)
	obtained, err := p.parseMsgId()

	expectError(err, e)
	Expect(obtained).To(Equal(msgId))
	Expect(p.cursor).To(Equal(expC))
}

func assertParseSdName(sdData string, b []byte, expC int, e error) {
	cursor := 0
	obtained, err := parseStructuredData(b, &cursor, len(b))

	expectError(err, e)
	Expect(obtained).To(Equal(sdData))
	Expect(cursor).To(Equal(expC))
}

func expectError(obtained error, expected error) {
	if expected == nil {
		Expect(obtained).To(BeNil())
		return
	}
	Expect(obtained).To(Equal(expected))
}

var _ = Describe("RFC5424 parser", func() {
	It("parser valid", testParser_Valid)
	It("parser truncated", testParser_Truncated)
	It("parse header valid", testParseHeader_Valid)
	It("parse header invalid proc id", testParseHeader_InvalidProcID)
	It("parse header invalid msg id", testParseHeader_InvalidMsgID)
	It("parse timestamp utc", testParseTimestamp_UTC)
	It("parse timestamp numeric timezone", testParseTimestamp_NumericTimezone)
	It("parse timestamp milli seconds", testParseTimestamp_MilliSeconds)
	It("parse timestamp micro seconds", testParseTimestamp_MicroSeconds)
	It("parse timestamp nano seconds", testParseTimestamp_NanoSeconds)
	It("parse timestamp nil value", testParseTimestamp_NilValue)
	It("parse timestamp empty", testParseTimestamp_Empty)
	It("find next space no space", testFindNextSpace_NoSpace)
	It("find next space space found", testFindNextSpace_SpaceFound)
	It("parse year invalid", testParseYear_Invalid)
	It("parse year too short", testParseYear_TooShort)
	It("parse year valid", testParseYear_Valid)
	It("parse month invalid string", testParseMonth_InvalidString)
	It("parse month invalid range", testParseMonth_InvalidRange)
	It("parse month too short", testParseMonth_TooShort)
	It("parse month valid", testParseMonth_Valid)
	It("parse day invalid string", testParseDay_InvalidString)
	It("parse day too short", testParseDay_TooShort)
	It("parse day invalid range", testParseDay_InvalidRange)
	It("parse day valid", testParseDay_Valid)
	It("parse full date invalid", testParseFullDate_Invalid)
	It("parse full date valid", testParseFullDate_Valid)
	It("parse hour invalid string", testParseHour_InvalidString)
	It("parse hour too short", testParseHour_TooShort)
	It("parse hour invalid range", testParseHour_InvalidRange)
	It("parse hour valid", testParseHour_Valid)
	It("parse minute invalid string", testParseMinute_InvalidString)
	It("parse minute too short", testParseMinute_TooShort)
	It("parse minute invalid range", testParseMinute_InvalidRange)
	It("parse minute valid", testParseMinute_Valid)
	It("parse second invalid string", testParseSecond_InvalidString)
	It("parse second too short", testParseSecond_TooShort)
	It("parse second invalid range", testParseSecond_InvalidRange)
	It("parse second valid", testParseSecond_Valid)
	It("parse sec frac invalid string", testParseSecFrac_InvalidString)
	It("parse sec frac nano seconds", testParseSecFrac_NanoSeconds)
	It("parse sec frac valid", testParseSecFrac_Valid)
	It("parse numerical time offset valid", testParseNumericalTimeOffset_Valid)
	It("parse time offset valid", testParseTimeOffset_Valid)
	It("get hour min valid", testGetHourMin_Valid)
	It("parse partial time valid", testParsePartialTime_Valid)
	It("parse full time valid", testParseFullTime_Valid)
	It("to nsec", testToNSec)
	It("parse app name valid", testParseAppName_Valid)
	It("parse app name too long", testParseAppName_TooLong)
	It("parse proc id valid", testParseProcId_Valid)
	It("parse proc id too long", testParseProcId_TooLong)
	It("parse msg id valid", testParseMsgId_Valid)
	It("parse msg id too long", testParseMsgId_TooLong)
	It("parse structured data nil value", testParseStructuredData_NilValue)
	It("parse structured data single structured data", testParseStructuredData_SingleStructuredData)
	It("parse structured data multiple structured data", testParseStructuredData_MultipleStructuredData)
	It("parse structured data multiple structured data invalid", testParseStructuredData_MultipleStructuredDataInvalid)
})
