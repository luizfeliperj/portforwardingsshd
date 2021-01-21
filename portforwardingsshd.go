package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	retries       = 10
	maxAuthTries  = 3
	serverVersion = "SSH-2.0-OpenSSH_8.4p1"
)

var (
	listeners map[uint32]chan struct{}
	lock      *sync.Mutex
)

type stBindInfo struct {
	Addr string
	Port uint32
}

type stDirectInfo struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

func getRSAKeys() (*rsa.PublicKey, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	return &privateKey.PublicKey, privateKey, nil
}

func copyTimeout(dst io.Writer, src io.Reader, timeout func()) (written int64, err error) {
	buf := make([]byte, 32*1024)

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			timeout()

			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
			timeout()
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

func serve(channel ssh.Channel, conn net.Conn, client *ssh.ServerConn, timeout time.Duration) {
	var once sync.Once

	close := func() {
		channel.Close()
		conn.Close()
		log.Printf("[%v] Channel closed.", client)
	}

	go func() {
		bytesWritten, err := copyTimeout(channel, conn, func() {
			conn.SetDeadline(time.Now().Add(timeout))
		})
		if err != nil {
			log.Printf("[%v] copyTimeout failed with: %s, written %v",
				client, err.Error(), bytesWritten)
		}
		once.Do(close)
	}()

	go func() {
		bytesWritten, err := copyTimeout(conn, channel, func() {
			conn.SetDeadline(time.Now().Add(timeout))
		})
		if err != nil {
			log.Printf("[%v] copyTimeout failed with: %s, written %v",
				client, err.Error(), bytesWritten)
		}

		once.Do(close)
	}()
}

func handleDirectTCPIP(sConn *ssh.ServerConn, newChan ssh.NewChannel, info *stDirectInfo) {
	dest := net.JoinHostPort(
		info.DestAddr,
		strconv.FormatInt(int64(info.DestPort), 10),
	)

	dconn, err := net.DialTimeout("tcp", dest, time.Minute)
	if err != nil {
		newChan.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		dconn.Close()
		return
	}

	go ssh.DiscardRequests(reqs)
	go serve(ch, dconn, sConn, time.Minute)
}

func handleForwardTCPIP(sConn *ssh.ServerConn, req *ssh.Request, payload []byte) {
	r := stBindInfo{}

	if err := ssh.Unmarshal(payload, &r); err != nil {
		log.Printf("Request unmarshalling error: %v", err.Error())
		return
	}

	req.Reply(
		true,
		ssh.Marshal(&struct{ uint32 }{r.Port}),
	)

	go func(addr string, port uint32) {
		var listener net.Listener

		if v, ok := listeners[port]; ok {
			v <- struct{}{}
		}

		for i := 0; i < retries; i++ {
			var err error

			listener, err = net.Listen("tcp", net.JoinHostPort(addr, fmt.Sprintf("%d", port)))
			if err != nil {
				if i < retries-1 {
					log.Printf("handleRequests: net.Listen returned: %v", err.Error())
					time.Sleep(time.Second)
					continue
				}

				log.Fatalf("handleRequests: net.Listen returned: %v", err.Error())
			}
			break
		}

		lock.Lock()
		listeners[port] = make(chan struct{})
		lock.Unlock()

		go func(port uint32) {
			<-listeners[port]

			lock.Lock()
			delete(listeners, port)
			lock.Unlock()

			log.Printf("handleRequests: Drop listener from %v", port)

			listener.Close()
		}(port)

		for {
			conn, err := listener.Accept()
			if err != nil {
				e := err.Error()
				useofclosed := "use of closed network connection"
				if 0 == strings.Compare(e[len(e)-len(useofclosed):], useofclosed) {
					break
				}

				log.Printf("handleRequests: Error accepting incoming connection: %v", err)
				continue
			}

			go serveForwardTCPIP(sConn, &r, conn)
			log.Printf("Handling forward: %v:%v", r.Addr, r.Port)
		}
	}(r.Addr, r.Port)
}

func serveForwardTCPIP(sConn *ssh.ServerConn, bindinfo *stBindInfo, lconn net.Conn) {
	remotetcpaddr := lconn.RemoteAddr().(*net.TCPAddr)
	raddr := remotetcpaddr.IP.String()
	rport := uint32(remotetcpaddr.Port)

	payload := stDirectInfo{
		bindinfo.Addr,
		bindinfo.Port,
		raddr,
		uint32(rport),
	}
	mpayload := ssh.Marshal(&payload)

	c, requests, err := sConn.OpenChannel("forwarded-tcpip", mpayload)
	if err != nil {
		log.Printf("[%v] Unable to get channel: %s. Hanging up requesting party!", sConn, err)
		lconn.Close()
		return
	}

	log.Printf("[%v] Channel opened for client %v", sConn, c)
	go ssh.DiscardRequests(requests)
	go serve(c, lconn, sConn, time.Minute)
}

func handleRequests(sConn *ssh.ServerConn, chans <-chan *ssh.Request) {
	for req := range chans {
		switch req.Type {
		case "tcpip-forward":
			handleForwardTCPIP(sConn, req, req.Payload)

		case "keepalive@openssh.com":
			fallthrough
		case "keepalive@golang.org":
			req.Reply(
				true,
				nil,
			)

		default:
			log.Printf("handleRequests: Dunno %v", req.Type)
			fallthrough

		case "no-more-sessions@openssh.com":
			if req.WantReply {
				req.Reply(false, []byte{})
			}
		}
	}
}

func handleServerConn(sConn *ssh.ServerConn, chans <-chan ssh.NewChannel) {
	for newChan := range chans {
		switch newChan.ChannelType() {
		case "direct-tcpip":
			d := &stDirectInfo{}

			if e := ssh.Unmarshal(newChan.ExtraData(), d); e != nil {
				newChan.Reject(
					ssh.ConnectionFailed,
					fmt.Sprintf(
						"Error parsing forward data: %v",
						e.Error(),
					),
				)
			}

			handleDirectTCPIP(sConn, newChan, d)

		default:
			log.Printf("handleRequests: Dunno %v", newChan.ChannelType())
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

func handleListen(config *ssh.ServerConfig, host string, port int) {

	ip := net.JoinHostPort(host, fmt.Sprintf("%v", port))
	listener, err := net.Listen("tcp", ip)
	if err != nil {
		log.Fatalf("Failed to start SSH server: %v", err)
	} else {
		log.Printf("Server up listening on %v", ip)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("SSH: Error accepting incoming connection: %v", err)
			continue
		}

		go func() {
			defer conn.Close()

			log.Printf("SSH: Handshaking for %s", conn.RemoteAddr())
			/* time.Sleep(15 * time.Second) */
			sConn, chans, reqs, err := ssh.NewServerConn(conn, config)
			if err != nil {
				if err == io.EOF {
					log.Printf("SSH: Handshaking was terminated by EOF: %v", err)
				} else if strings.Contains(err.Error(), "no common algorithm for host key") {
					log.Printf("SSH: Handshaking was terminated by failed auth: %v", err)
				} else if strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("SSH: Handshaking was terminated by closed conn: %v", err)
				} else if strings.Contains(err.Error(), "invalid packet length") {
					log.Printf("SSH: Handshaking was terminated: %v", err)
				} else if strings.Contains(err.Error(), "connection reset by peer") {
					log.Printf("SSH: Handshaking was terminated: %v", err)
				} else if strings.Contains(err.Error(), "no auth passed yet") {
					log.Printf("SSH: Auth handshaking was terminated: %v", err)
				} else {
					log.Fatalf("SSH: Error on handshaking: %v", err)
				}
				return
			}

			defer sConn.Close()

			log.Printf("SSH: Connection from %v@%s (%s)",
				sConn.User(),
				sConn.RemoteAddr(),
				sConn.ClientVersion(),
			)

			go handleRequests(sConn, reqs)
			go handleServerConn(sConn, chans)

			if e := sConn.Wait(); e != nil {
				log.Printf("sConn Wait err %v", e.Error())
			}
		}()
	}
}

func listen(host string, port int, ciphers []string) {
	authPrivKeyBuffer := &bytes.Buffer{}

	authPubKey, authPrivKey, err := getRSAKeys()
	if err != nil {
		log.Fatalf("Error getting auth keys %v", err)
	}

	authKey, err := ssh.NewPublicKey(authPubKey)
	if err != nil {
		log.Fatalf("Error getting NewPublicKey %v", err)
	}

	sshPubKey, sshPrivKey, err := getRSAKeys()
	if err != nil {
		log.Fatalf("Error getting hosts keys %v", err)
	}

	sshPrivSigner, err := ssh.NewSignerFromKey(sshPrivKey)
	if err != nil {
		log.Fatalf("Error getting private signer %v", err)
	}

	hostPubKey, err := ssh.NewPublicKey(sshPubKey)
	if err != nil {
		log.Fatalf("Error getting public key %v", err)
	}

	err = pem.Encode(
		authPrivKeyBuffer,
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(authPrivKey),
		},
	)
	if err != nil {
		log.Fatalf("pem.Encode: %v", err)
	}

	config := &ssh.ServerConfig{
		Config: ssh.Config{
			Ciphers: ciphers,
		},
		MaxAuthTries:  maxAuthTries,
		ServerVersion: serverVersion,
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(
				key.Marshal(),
				authKey.Marshal(),
			) {
				return &ssh.Permissions{
					Extensions: map[string]string{},
				}, nil
			}
			return nil, fmt.Errorf("Unauthorized")
		},
	}

	config.AddHostKey(sshPrivSigner)

	log.Printf("Connect using this private key:\n%v",
		authPrivKeyBuffer.String(),
	)

	log.Printf("Add to .ssh/known_hosts (%v):\n%s:%d %s",
		ssh.FingerprintSHA256(hostPubKey),
		host, port,
		ssh.MarshalAuthorizedKey(hostPubKey),
	)

	handleListen(config, host, port)
}

func main() {
	lock = &sync.Mutex{}
	listeners = make(map[uint32]chan struct{})

	listen("", 2022, []string{
		"aes256-ctr",
		"aes128-ctr",
	})
}
