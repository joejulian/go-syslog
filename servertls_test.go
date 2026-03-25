package syslog

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func generateTLSConfig() (*tls.Config, *tls.Config) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "dummycert1",
		},
		DNSNames:              []string{"dummycert1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(certPEM); !ok {
		panic("failed to append certificate to pool")
	}

	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	clientConfig := &tls.Config{
		ServerName: "dummycert1",
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}

	return serverConfig, clientConfig
}

var _ = Describe("TLS server", func() {
	It("handles TLS connections and reports the peer name", func() {
		serverConfig, clientConfig := generateTLSConfig()
		handled := make(chan struct{})
		handler := &handlerMock{called: handled}
		server := NewServer()
		server.SetFormat(RFC3164)
		server.SetHandler(handler)
		server.SetTlsPeerNameFunc(func(*tls.Conn) (string, bool) {
			return "dummycert1", true
		})
		Expect(server.ListenTCPTLS("127.0.0.1:0", serverConfig)).To(Succeed())

		Expect(server.Boot()).To(Succeed())
		go func(addr string) {
			defer GinkgoRecover()
			conn, err := tls.Dial("tcp", addr, clientConfig)
			Expect(err).NotTo(HaveOccurred())
			defer conn.Close()
			_, err = io.WriteString(conn, fmt.Sprintf("%s\n", exampleSyslog))
			Expect(err).NotTo(HaveOccurred())
		}(server.listeners[0].Addr().String())

		Eventually(handled, 2*time.Second).Should(BeClosed())
		Expect(server.Kill()).To(Succeed())
		server.Wait()

		Expect(handler.lastLogParts["hostname"]).To(Equal("hostname"))
		Expect(handler.lastLogParts["tag"]).To(Equal("tag"))
		Expect(handler.lastLogParts["content"]).To(Equal("content"))
		Expect(handler.lastLogParts["tls_peer"]).To(Equal("dummycert1"))
		Expect(handler.lastMessageLength).To(Equal(int64(len(exampleSyslog))))
		Expect(handler.lastError).NotTo(HaveOccurred())
	})
})
