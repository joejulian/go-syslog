package format

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RFC6587", func() {
	It("splits a single octet-counted frame", func() {
		f := RFC6587{}

		buf := strings.NewReader("10 I am test.")
		scanner := bufio.NewScanner(buf)
		scanner.Split(f.GetSplitFunc())

		Expect(scanner.Scan()).To(BeTrue())
		Expect(scanner.Text()).To(Equal("I am test."))
	})

	It("splits multiple octet-counted frames", func() {
		f := RFC6587{}

		frames := []string{
			"I am test.",
			"I am test 2.",
			"hahahahah",
		}
		buf := new(bytes.Buffer)
		for _, frame := range frames {
			fmt.Fprintf(buf, "%d %s", len(frame), frame)
		}
		scanner := bufio.NewScanner(buf)
		scanner.Split(f.GetSplitFunc())

		i := 0
		for scanner.Scan() {
			Expect(scanner.Text()).To(Equal(frames[i]))
			i++
		}

		Expect(i).To(Equal(len(frames)))
	})

	It("treats non-transparent framing as a single frame", func() {
		f := RFC6587{}

		frames := []string{
			"<1> I am a test.",
			"<2> I am a test 2.",
			"<3> hahahah",
		}
		buf := new(bytes.Buffer)
		for _, frame := range frames {
			fmt.Fprintf(buf, "%s", frame)
		}
		scanner := bufio.NewScanner(buf)
		scanner.Split(f.GetSplitFunc())

		i := 0
		for scanner.Scan() {
			Expect(scanner.Text()).To(Equal(strings.Join(frames, "")))
			i++
		}

		Expect(i).To(Equal(1))
	})

	It("returns an error when the octet count is invalid", func() {
		f := RFC6587{}

		find := "I am test.2 ab"
		buf := strings.NewReader("9 " + find)
		scanner := bufio.NewScanner(buf)
		scanner.Split(f.GetSplitFunc())

		Expect(scanner.Scan()).To(BeTrue())
		Expect(scanner.Text()).To(Equal(find[0:9]))
		scanner.Scan()
		Expect(scanner.Err()).To(MatchError(MatchRegexp("invalid syntax")))
	})
})
