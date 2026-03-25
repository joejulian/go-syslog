package syslog

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/joejulian/go-syslog/v2/format"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type noopHandler struct{}

func (noopHandler) Handle(format.LogParts, int64, error) {}

type handlerMock struct {
	lastLogParts      format.LogParts
	lastMessageLength int64
	lastError         error
	called            chan struct{}
	onHandle          func(format.LogParts, int64, error)
}

func (h *handlerMock) Handle(logParts format.LogParts, msgLen int64, err error) {
	h.lastLogParts = logParts
	h.lastMessageLength = msgLen
	h.lastError = err
	if h.onHandle != nil {
		h.onHandle(logParts, msgLen, err)
	}
	if h.called != nil {
		select {
		case <-h.called:
		default:
			close(h.called)
		}
	}
}

type connMock struct {
	readData       []byte
	returnTimeout  bool
	isClosed       bool
	isReadDeadline bool
}

func (c *connMock) Read(b []byte) (n int, err error) {
	if c.returnTimeout {
		return 0, net.UnknownNetworkError("i/o timeout")
	}
	if c.readData != nil {
		l := copy(b, c.readData)
		c.readData = c.readData[l:]
		if len(c.readData) == 0 {
			c.readData = nil
		}
		return l, nil
	}
	return 0, io.EOF
}

func (c *connMock) Write([]byte) (n int, err error) { return 0, nil }
func (c *connMock) Close() error                    { c.isClosed = true; return nil }
func (c *connMock) LocalAddr() net.Addr             { return nil }
func (c *connMock) RemoteAddr() net.Addr            { return nil }
func (c *connMock) SetDeadline(time.Time) error     { return nil }
func (c *connMock) SetReadDeadline(time.Time) error { c.isReadDeadline = true; return nil }
func (c *connMock) SetWriteDeadline(time.Time) error {
	return nil
}

type countingHandler struct {
	count    int
	expected int
	done     chan struct{}
}

func (h *countingHandler) Handle(format.LogParts, int64, error) {
	h.count++
	if h.count == h.expected {
		close(h.done)
	}
}

type handlerSlow struct {
	*countingHandler
	contents []string
}

func (h *handlerSlow) Handle(logParts format.LogParts, msgLen int64, err error) {
	if len(h.contents) == 0 {
		time.Sleep(time.Second)
	}
	h.contents = append(h.contents, logParts["content"].(string))
	h.countingHandler.Handle(logParts, msgLen, err)
}

var (
	exampleSyslog            = "<31>Dec 26 05:08:46 hostname tag[296]: content"
	exampleSyslogNoTSTagHost = "<14>INFO     leaving (1) step postscripts"
	exampleSyslogNoPriority  = "Dec 26 05:08:46 hostname test with no priority - see rfc 3164 section 4.3.3"
	exampleRFC5424Syslog     = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8"
	malformedRFC5424Syslog   = "<34>1 not-a-timestamp mymachine.example.com su - ID47 - malformed timestamp"
)

var _ = Describe("Server", func() {
	It("synchronizes concurrent last-error access", func() {
		server := NewServer()
		server.SetFormat(RFC5424)
		server.SetHandler(noopHandler{})

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(2)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				server.parser([]byte("<34>1 not-a-timestamp host app proc msg -"), "127.0.0.1", "")
			}()
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				_ = server.GetLastError()
			}()
		}
		wg.Wait()
	})

	It("receives a UDP message", func() {
		handled := make(chan struct{})
		handler := &handlerMock{called: handled}
		server := NewServer()
		server.SetFormat(RFC3164)
		server.SetHandler(handler)
		err := server.ListenUDP("127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())

		Expect(server.Boot()).To(Succeed())
		serverAddr, err := net.ResolveUDPAddr("udp", server.connections[0].LocalAddr().String())
		Expect(err).NotTo(HaveOccurred())
		con, err := net.DialUDP("udp", nil, serverAddr)
		Expect(err).NotTo(HaveOccurred())
		defer con.Close()

		_, err = con.Write([]byte(exampleSyslog))
		Expect(err).NotTo(HaveOccurred())

		Eventually(handled).Should(BeClosed())
		Expect(server.Kill()).To(Succeed())
		server.Wait()

		Expect(handler.lastLogParts["hostname"]).To(Equal("hostname"))
		Expect(handler.lastLogParts["tag"]).To(Equal("tag"))
		Expect(handler.lastLogParts["content"]).To(Equal("content"))
		Expect(handler.lastMessageLength).To(Equal(int64(len(exampleSyslog))))
		Expect(handler.lastError).NotTo(HaveOccurred())
	})

	It("closes a scanned connection after processing", func() {
		handler := new(handlerMock)
		server := NewServer()
		server.SetFormat(RFC3164)
		server.SetHandler(handler)
		con := connMock{readData: []byte(exampleSyslog)}
		server.goScanConnection(&con)
		server.Wait()
		Expect(con.isClosed).To(BeTrue())
	})

	It("closes a connection when killed", func() {
		handler := new(handlerMock)
		server := NewServer()
		server.SetFormat(RFC5424)
		server.SetHandler(handler)
		con := connMock{readData: []byte(exampleSyslog)}
		server.goScanConnection(&con)
		Expect(server.Kill()).To(Succeed())
		server.Wait()
		Expect(con.isClosed).To(BeTrue())
	})

	It("ignores timeouts while scanning", func() {
		handler := new(handlerMock)
		server := NewServer()
		server.SetFormat(RFC3164)
		server.SetHandler(handler)
		server.SetTimeout(10)
		con := connMock{readData: []byte(exampleSyslog), returnTimeout: true}
		Expect(con.isReadDeadline).To(BeFalse())
		server.goScanConnection(&con)
		server.Wait()
		Expect(con.isReadDeadline).To(BeTrue())
		Expect(handler.lastLogParts).To(BeNil())
		Expect(handler.lastMessageLength).To(Equal(int64(0)))
		Expect(handler.lastError).NotTo(HaveOccurred())
	})

	It("parses RFC3164 datagrams", func() {
		handler := new(handlerMock)
		server := NewServer()
		server.SetFormat(RFC3164)
		server.SetHandler(handler)
		server.SetTimeout(10)
		server.goParseDatagrams()
		server.datagramChannel <- DatagramMessage{[]byte(exampleSyslog), "0.0.0.0"}
		close(server.datagramChannel)
		server.Wait()
		Expect(handler.lastLogParts["hostname"]).To(Equal("hostname"))
		Expect(handler.lastLogParts["tag"]).To(Equal("tag"))
		Expect(handler.lastLogParts["content"]).To(Equal("content"))
		Expect(handler.lastMessageLength).To(Equal(int64(len(exampleSyslog))))
		Expect(handler.lastError).NotTo(HaveOccurred())
	})

	It("infers the hostname for RFC3164 messages without a tag", func() {
		handler := new(handlerMock)
		server := NewServer()
		server.SetFormat(RFC3164)
		server.SetHandler(handler)
		server.SetTimeout(10)
		server.goParseDatagrams()
		server.datagramChannel <- DatagramMessage{[]byte(exampleSyslogNoTSTagHost), "127.0.0.1:45789"}
		close(server.datagramChannel)
		server.Wait()
		Expect(handler.lastLogParts["hostname"]).To(Equal("127.0.0.1"))
		Expect(handler.lastLogParts["hostname_inferred"]).To(Equal(true))
		Expect(handler.lastLogParts["tag"]).To(Equal(""))
		Expect(handler.lastLogParts["content"]).To(Equal("INFO     leaving (1) step postscripts"))
		Expect(handler.lastMessageLength).To(Equal(int64(len(exampleSyslogNoTSTagHost))))
		Expect(handler.lastError).NotTo(HaveOccurred())
	})

	It("marks inferred RFC3164 priority and timestamp in automatic mode", func() {
		handler := new(handlerMock)
		server := NewServer()
		server.SetFormat(Automatic)
		server.SetHandler(handler)
		server.SetTimeout(10)
		server.goParseDatagrams()
		server.datagramChannel <- DatagramMessage{[]byte(exampleSyslogNoPriority), "127.0.0.1:45789"}
		close(server.datagramChannel)
		server.Wait()
		Expect(handler.lastLogParts["hostname"]).To(Equal("127.0.0.1"))
		Expect(handler.lastLogParts["tag"]).To(Equal(""))
		Expect(handler.lastLogParts["priority"]).To(Equal(13))
		Expect(handler.lastLogParts["content"]).To(Equal(exampleSyslogNoPriority))
		Expect(handler.lastLogParts["raw"]).To(Equal(exampleSyslogNoPriority))
		Expect(handler.lastLogParts["priority_inferred"]).To(Equal(true))
		Expect(handler.lastLogParts["timestamp_inferred"]).To(Equal(true))
		Expect(handler.lastMessageLength).To(Equal(int64(len(exampleSyslogNoPriority))))
		Expect(handler.lastError).NotTo(HaveOccurred())
	})

	It("includes parse errors and raw payloads for malformed automatic messages", func() {
		handler := new(handlerMock)
		server := NewServer()
		server.SetFormat(Automatic)
		server.SetHandler(handler)
		server.SetTimeout(10)
		server.goParseDatagrams()
		server.datagramChannel <- DatagramMessage{[]byte(malformedRFC5424Syslog), "127.0.0.1:45789"}
		close(server.datagramChannel)
		server.Wait()
		Expect(handler.lastLogParts["raw"]).To(Equal(malformedRFC5424Syslog))
		Expect(handler.lastLogParts["parse_error"]).NotTo(BeNil())
		Expect(handler.lastLogParts["tls_peer"]).To(Equal(""))
		Expect(handler.lastError).To(HaveOccurred())
	})

	It("handles large frames without truncating the payload", func() {
		handler := new(handlerMock)
		server := NewServer()
		server.SetFormat(RFC3164)
		server.SetHandler(handler)

		largeContent := strings.Repeat("x", 128*1024)
		message := fmt.Sprintf("<31>Dec 26 05:08:46 hostname tag[296]: %s", largeContent)
		con := connMock{readData: []byte(message)}
		server.goScanConnection(&con)
		server.Wait()

		Expect(con.isClosed).To(BeTrue())
		Expect(len(handler.lastLogParts["raw"].(string))).To(Equal(len(message)))
		Expect(handler.lastLogParts["content"]).To(Equal(largeContent))
		Expect(handler.lastError).NotTo(HaveOccurred())
	})

	It("parses RFC6587 datagrams", func() {
		handler := new(handlerMock)
		server := NewServer()
		server.SetFormat(RFC6587)
		server.SetHandler(handler)
		server.SetTimeout(10)
		server.goParseDatagrams()
		framedSyslog := []byte(fmt.Sprintf("%d %s", len(exampleRFC5424Syslog), exampleRFC5424Syslog))
		server.datagramChannel <- DatagramMessage{framedSyslog, "0.0.0.0"}
		close(server.datagramChannel)
		server.Wait()
		Expect(handler.lastLogParts["hostname"]).To(Equal("mymachine.example.com"))
		Expect(handler.lastLogParts["facility"]).To(Equal(4))
		Expect(handler.lastLogParts["message"]).To(Equal("'su root' failed for lonvick on /dev/pts/8"))
		Expect(handler.lastMessageLength).To(Equal(int64(len(exampleRFC5424Syslog))))
		Expect(handler.lastError).NotTo(HaveOccurred())
	})

	It("auto-detects RFC3164 datagrams", func() {
		handler := new(handlerMock)
		server := NewServer()
		server.SetFormat(Automatic)
		server.SetHandler(handler)
		server.SetTimeout(10)
		server.goParseDatagrams()
		server.datagramChannel <- DatagramMessage{[]byte(exampleSyslog), "0.0.0.0"}
		close(server.datagramChannel)
		server.Wait()
		Expect(handler.lastLogParts["hostname"]).To(Equal("hostname"))
		Expect(handler.lastLogParts["tag"]).To(Equal("tag"))
		Expect(handler.lastLogParts["content"]).To(Equal("content"))
		Expect(handler.lastMessageLength).To(Equal(int64(len(exampleSyslog))))
		Expect(handler.lastError).NotTo(HaveOccurred())
	})

	It("auto-detects RFC5424 datagrams", func() {
		handler := new(handlerMock)
		server := NewServer()
		server.SetFormat(Automatic)
		server.SetHandler(handler)
		server.SetTimeout(10)
		server.goParseDatagrams()
		server.datagramChannel <- DatagramMessage{[]byte(exampleRFC5424Syslog), "0.0.0.0"}
		close(server.datagramChannel)
		server.Wait()
		Expect(handler.lastLogParts["hostname"]).To(Equal("mymachine.example.com"))
		Expect(handler.lastLogParts["facility"]).To(Equal(4))
		Expect(handler.lastLogParts["message"]).To(Equal("'su root' failed for lonvick on /dev/pts/8"))
		Expect(handler.lastMessageLength).To(Equal(int64(len(exampleRFC5424Syslog))))
		Expect(handler.lastError).NotTo(HaveOccurred())
	})

	It("auto-detects RFC3164 messages wrapped with RFC6587 octet counts", func() {
		handler := new(handlerMock)
		server := NewServer()
		server.SetFormat(Automatic)
		server.SetHandler(handler)
		server.SetTimeout(10)
		server.goParseDatagrams()
		framedSyslog := []byte(fmt.Sprintf("%d %s", len(exampleSyslog), exampleSyslog))
		server.datagramChannel <- DatagramMessage{framedSyslog, "0.0.0.0"}
		close(server.datagramChannel)
		server.Wait()
		Expect(handler.lastLogParts["hostname"]).To(Equal("hostname"))
		Expect(handler.lastLogParts["tag"]).To(Equal("tag"))
		Expect(handler.lastLogParts["content"]).To(Equal("content"))
		Expect(handler.lastMessageLength).To(Equal(int64(len(exampleSyslog))))
		Expect(handler.lastError).NotTo(HaveOccurred())
	})

	It("shuts down cleanly with inflight datagrams", func() {
		handler := new(handlerMock)
		server := NewServer()
		server.SetFormat(RFC3164)
		server.SetHandler(handler)
		server.SetDatagramChannelSize(0)
		Expect(server.ListenUDP("127.0.0.1:0")).To(Succeed())

		var killOnce sync.Once
		killErr := make(chan error, 1)
		handler.onHandle = func(format.LogParts, int64, error) {
			killOnce.Do(func() {
				time.Sleep(50 * time.Millisecond)
				killErr <- server.Kill()
			})
		}

		Expect(server.Boot()).To(Succeed())

		serverAddr, err := net.ResolveUDPAddr("udp", server.connections[0].LocalAddr().String())
		Expect(err).NotTo(HaveOccurred())
		con, err := net.DialUDP("udp", nil, serverAddr)
		Expect(err).NotTo(HaveOccurred())
		defer con.Close()

		_, err = con.Write([]byte(exampleSyslog))
		Expect(err).NotTo(HaveOccurred())
		_, err = con.Write([]byte(exampleSyslog))
		Expect(err).NotTo(HaveOccurred())

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			server.Wait()
			close(done)
		}()

		Eventually(done).Should(BeClosed())
		var gotErr error
		Eventually(killErr).Should(Receive(&gotErr))
		Expect(gotErr).NotTo(HaveOccurred())
		Expect(handler.lastLogParts["hostname"]).To(Equal("hostname"))
	})

	It("auto-detects RFC5424 messages wrapped with RFC6587 octet counts", func() {
		handler := new(handlerMock)
		server := NewServer()
		server.SetFormat(Automatic)
		server.SetHandler(handler)
		server.SetTimeout(10)
		server.goParseDatagrams()
		framedSyslog := []byte(fmt.Sprintf("%d %s", len(exampleRFC5424Syslog), exampleRFC5424Syslog))
		server.datagramChannel <- DatagramMessage{framedSyslog, "0.0.0.0"}
		close(server.datagramChannel)
		server.Wait()
		Expect(handler.lastLogParts["hostname"]).To(Equal("mymachine.example.com"))
		Expect(handler.lastLogParts["facility"]).To(Equal(4))
		Expect(handler.lastLogParts["message"]).To(Equal("'su root' failed for lonvick on /dev/pts/8"))
		Expect(handler.lastMessageLength).To(Equal(int64(len(exampleRFC5424Syslog))))
		Expect(handler.lastError).NotTo(HaveOccurred())
	})

	It("preserves UDP ordering even with a slow handler", func() {
		handler := &handlerSlow{countingHandler: &countingHandler{expected: 3, done: make(chan struct{})}}
		server := NewServer()
		server.SetFormat(Automatic)
		server.SetHandler(handler)
		server.SetTimeout(10)
		Expect(server.ListenUDP("127.0.0.1:0")).To(Succeed())
		Expect(server.Boot()).To(Succeed())
		conn, err := net.Dial("udp", server.connections[0].LocalAddr().String())
		Expect(err).NotTo(HaveOccurred())
		_, err = conn.Write([]byte(exampleSyslog + "1"))
		Expect(err).NotTo(HaveOccurred())
		_, err = conn.Write([]byte(exampleSyslog + "2"))
		Expect(err).NotTo(HaveOccurred())
		_, err = conn.Write([]byte(exampleSyslog + "3"))
		Expect(err).NotTo(HaveOccurred())
		Expect(conn.Close()).To(Succeed())
		Eventually(handler.done, 5*time.Second).Should(BeClosed())
		Expect(handler.contents).To(Equal([]string{"content1", "content2", "content3"}))
	})

	It("preserves TCP ordering even with a slow handler", func() {
		handler := &handlerSlow{countingHandler: &countingHandler{expected: 3, done: make(chan struct{})}}
		server := NewServer()
		server.SetFormat(Automatic)
		server.SetHandler(handler)
		server.SetTimeout(10)
		Expect(server.ListenTCP("127.0.0.1:0")).To(Succeed())
		Expect(server.Boot()).To(Succeed())
		conn, err := net.Dial("tcp", server.listeners[0].Addr().String())
		Expect(err).NotTo(HaveOccurred())
		_, err = conn.Write([]byte(exampleSyslog + "1\n"))
		Expect(err).NotTo(HaveOccurred())
		_, err = conn.Write([]byte(exampleSyslog + "2\n"))
		Expect(err).NotTo(HaveOccurred())
		_, err = conn.Write([]byte(exampleSyslog + "3\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(conn.Close()).To(Succeed())
		Eventually(handler.done, 5*time.Second).Should(BeClosed())
		Expect(handler.contents).To(Equal([]string{"content1", "content2", "content3"}))
	})
})
