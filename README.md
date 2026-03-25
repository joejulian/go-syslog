go-syslog [![CI](https://github.com/joejulian/go-syslog/actions/workflows/ci.yml/badge.svg)](https://github.com/joejulian/go-syslog/actions/workflows/ci.yml) [![Go Reference](https://pkg.go.dev/badge/github.com/joejulian/go-syslog/v2.svg)](https://pkg.go.dev/github.com/joejulian/go-syslog/v2)
==============================

Syslog server library for go, build easy your custom syslog server over UDP, TCP or Unix sockets using RFC3164, RFC6587 or RFC5424

Installation
------------

The recommended way to install go-syslog

```bash
go get github.com/joejulian/go-syslog/v2
```

Examples
--------

How import the package

```go
import "github.com/joejulian/go-syslog/v2"
```

Example of a basic syslog [UDP server](example/basic_udp.go):

```go
channel := make(syslog.LogPartsChannel)
handler := syslog.NewChannelHandler(channel)

server := syslog.NewServer()
server.SetFormat(syslog.RFC5424)
server.SetHandler(handler)
server.ListenUDP("0.0.0.0:514")
server.Boot()

go func(channel syslog.LogPartsChannel) {
    for logParts := range channel {
        fmt.Println(logParts)
    }
}(channel)

server.Wait()
```

License
-------

MIT, see [LICENSE](LICENSE)
