package qtls

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type exportedKey struct {
	typ           string // "read" or "write"
	encLevel      EncryptionLevel
	suite         *CipherSuiteTLS13
	trafficSecret []byte
}

type recordLayer struct {
	in  <-chan []byte
	out chan<- interface{}
}

func (r *recordLayer) SetReadKey(encLevel EncryptionLevel, suite *CipherSuiteTLS13, trafficSecret []byte) {
	r.out <- &exportedKey{typ: "read", encLevel: encLevel, suite: suite, trafficSecret: trafficSecret}
}
func (r *recordLayer) SetWriteKey(encLevel EncryptionLevel, suite *CipherSuiteTLS13, trafficSecret []byte) {
	r.out <- &exportedKey{typ: "write", encLevel: encLevel, suite: suite, trafficSecret: trafficSecret}
}
func (r *recordLayer) ReadHandshakeMessage() ([]byte, error) { return <-r.in, nil }
func (r *recordLayer) WriteRecord(b []byte) (int, error)     { r.out <- b; return len(b), nil }
func (r *recordLayer) SendAlert(uint8)                       {}

type unusedConn struct{}

var _ net.Conn = &unusedConn{}

func (unusedConn) Read([]byte) (int, error)         { panic("unexpected call to Read()") }
func (unusedConn) Write([]byte) (int, error)        { panic("unexpected call to Write()") }
func (unusedConn) Close() error                     { return nil }
func (unusedConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (unusedConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (unusedConn) SetDeadline(time.Time) error      { return nil }
func (unusedConn) SetReadDeadline(time.Time) error  { return nil }
func (unusedConn) SetWriteDeadline(time.Time) error { return nil }

func TestAlternativeRecordLayer(t *testing.T) {
	sIn := make(chan []byte, 10)
	sOut := make(chan interface{}, 10)
	defer close(sOut)
	cIn := make(chan []byte, 10)
	cOut := make(chan interface{}, 10)
	defer close(cOut)

	serverEvents := make(chan interface{}, 100)
	go func() {
		for {
			c, ok := <-sOut
			if !ok {
				return
			}
			serverEvents <- c
			if b, ok := c.([]byte); ok {
				cIn <- b
			}
		}
	}()

	clientEvents := make(chan interface{}, 100)
	go func() {
		for {
			c, ok := <-cOut
			if !ok {
				return
			}
			clientEvents <- c
			if b, ok := c.([]byte); ok {
				sIn <- b
			}
		}
	}()

	errChan := make(chan error)
	go func() {
		config := testConfig.Clone()
		config.AlternativeRecordLayer = &recordLayer{in: sIn, out: sOut}
		tlsConn := Server(&unusedConn{}, config)
		defer tlsConn.Close()
		errChan <- tlsConn.Handshake()
	}()

	config := testConfig.Clone()
	config.AlternativeRecordLayer = &recordLayer{in: cIn, out: cOut}
	tlsConn := Client(&unusedConn{}, config)
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("Handshake failed: %s", err)
	}

	// Handshakes completed. Now check that events were received in the correct order.
	var clientHandshakeReadKey, clientHandshakeWriteKey *exportedKey
	var clientApplicationReadKey, clientApplicationWriteKey *exportedKey
	for i := 0; i <= 5; i++ {
		ev := <-clientEvents
		switch i {
		case 0:
			if ev.([]byte)[0] != typeClientHello {
				t.Fatalf("expected ClientHello")
			}
		case 1:
			keyEv := ev.(*exportedKey)
			if keyEv.typ != "write" || keyEv.encLevel != EncryptionHandshake {
				t.Fatalf("expected the handshake write key")
			}
			clientHandshakeWriteKey = keyEv
		case 2:
			keyEv := ev.(*exportedKey)
			if keyEv.typ != "read" || keyEv.encLevel != EncryptionHandshake {
				t.Fatalf("expected the handshake read key")
			}
			clientHandshakeReadKey = keyEv
		case 3:
			keyEv := ev.(*exportedKey)
			if keyEv.typ != "read" || keyEv.encLevel != EncryptionApplication {
				t.Fatalf("expected the application read key")
			}
			clientApplicationReadKey = keyEv
		case 4:
			if ev.([]byte)[0] != typeFinished {
				t.Fatalf("expected Finished")
			}
		case 5:
			keyEv := ev.(*exportedKey)
			if keyEv.typ != "write" || keyEv.encLevel != EncryptionApplication {
				t.Fatalf("expected the application write key")
			}
			clientApplicationWriteKey = keyEv
		}
	}
	if len(clientEvents) > 0 {
		t.Fatal("didn't expect any more client events")
	}

	compareKeys := func(k1, k2 *exportedKey) {
		if k1.encLevel != k2.encLevel || k1.suite.ID != k2.suite.ID || !bytes.Equal(k1.trafficSecret, k2.trafficSecret) {
			t.Fatal("mismatching keys")
		}
	}

	for i := 0; i <= 8; i++ {
		ev := <-serverEvents
		switch i {
		case 0:
			if ev.([]byte)[0] != typeServerHello {
				t.Fatalf("expected ServerHello")
			}
		case 1:
			keyEv := ev.(*exportedKey)
			if keyEv.typ != "read" || keyEv.encLevel != EncryptionHandshake {
				t.Fatalf("expected the handshake read key")
			}
			compareKeys(clientHandshakeWriteKey, keyEv)
		case 2:
			keyEv := ev.(*exportedKey)
			if keyEv.typ != "write" || keyEv.encLevel != EncryptionHandshake {
				t.Fatalf("expected the handshake write key")
			}
			compareKeys(clientHandshakeReadKey, keyEv)
		case 3:
			if ev.([]byte)[0] != typeEncryptedExtensions {
				t.Fatalf("expected EncryptedExtensions")
			}
		case 4:
			if ev.([]byte)[0] != typeCertificate {
				t.Fatalf("expected Certificate")
			}
		case 5:
			if ev.([]byte)[0] != typeCertificateVerify {
				t.Fatalf("expected CertificateVerify")
			}
		case 6:
			if ev.([]byte)[0] != typeFinished {
				t.Fatalf("expected Finished")
			}
		case 7:
			keyEv := ev.(*exportedKey)
			if keyEv.typ != "write" || keyEv.encLevel != EncryptionApplication {
				t.Fatalf("expected the application write key")
			}
			compareKeys(clientApplicationReadKey, keyEv)
		case 8:
			keyEv := ev.(*exportedKey)
			if keyEv.typ != "read" || keyEv.encLevel != EncryptionApplication {
				t.Fatalf("expected the application read key")
			}
			compareKeys(clientApplicationWriteKey, keyEv)
		}
	}
	if len(serverEvents) > 0 {
		t.Fatal("didn't expect any more server events")
	}
}
