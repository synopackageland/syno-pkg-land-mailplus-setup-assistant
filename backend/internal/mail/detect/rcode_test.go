package detect

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRCodeQueryAndReply(t *testing.T) {
	q, err := rcodeQuery(0x1234, "Mail.Example.test.")
	if err != nil {
		t.Fatal(err)
	}
	want := "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04Mail\x07Example\x04test\x00\x00\x06\x00\x01"
	if string(q) != want {
		t.Fatalf("query %q", q)
	}
	reply := func(id uint16, flags uint16, an uint16, question []byte) []byte {
		r := make([]byte, 12)
		binary.BigEndian.PutUint16(r[0:], id)
		binary.BigEndian.PutUint16(r[2:], flags)
		binary.BigEndian.PutUint16(r[4:], 1)
		binary.BigEndian.PutUint16(r[6:], an)
		return append(r, question...)
	}
	lower, _ := rcodeQuery(0x1234, "mail.example.test.")
	for _, tc := range []struct {
		name           string
		r              []byte
		rcode, answers int
		err            error
	}{
		{"nxdomain", reply(0x1234, 0x8183, 0, q[12:]), 3, 0, nil},
		{"nxdomain-with-cname", reply(0x1234, 0x8183, 1, q[12:]), 3, 1, nil},
		{"noerror-case-folded", reply(0x1234, 0x8180, 0, lower[12:]), 0, 0, nil},
		{"wrong-id", reply(0x9999, 0x8183, 0, q[12:]), 0, 0, errUnrelated},
		{"not-a-response", reply(0x1234, 0x0103, 0, q[12:]), 0, 0, errUnrelated},
		{"other-question", reply(0x1234, 0x8183, 0, []byte("\x01x\x04test\x00\x00\x06\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")), 0, 0, errUnrelated},
		{"short", q[:8], 0, 0, errUnrelated},
		// A truncated NXDOMAIN is not proof: unknown.
		{"truncated-nxdomain", reply(0x1234, 0x8383, 0, q[12:]), 0, 0, errTruncated},
		{"truncated-noerror", reply(0x1234, 0x8380, 0, q[12:]), 0, 0, errTruncated},
		// Opcode STATUS (2) and NOTIFY (4) are not answers to a QUERY.
		{"opcode-status", reply(0x1234, 0x9183, 0, q[12:]), 0, 0, errOpcode},
		{"opcode-notify", reply(0x1234, 0xa183, 0, q[12:]), 0, 0, errOpcode},
	} {
		rcode, answers, err := rcodeReply(q, tc.r)
		if err != tc.err || err == nil && (rcode != tc.rcode || answers != tc.answers) {
			t.Errorf("%s: %d %d %v", tc.name, rcode, answers, err)
		}
	}
}

func TestNameserversReadsAtMostThree(t *testing.T) {
	p := filepath.Join(t.TempDir(), "resolv.conf")
	os.WriteFile(p, []byte("# x\nsearch lan\nnameserver 192.0.2.53\nnameserver bogus\nnameserver fe80::1%eth0\nnameserver 192.0.2.54\nnameserver 192.0.2.55\n"), 0o600)
	got, err := nameservers(p)
	if err != nil || len(got) != 3 || got[0] != "192.0.2.53:53" || got[1] != "[fe80::1%eth0]:53" || got[2] != "192.0.2.54:53" {
		t.Fatalf("%v %v", got, err)
	}
	os.WriteFile(p, []byte("search lan\n"), 0o600)
	if _, err := nameservers(p); err == nil {
		t.Fatal("no nameserver must be an error (unknown), not a guess")
	}
}

// A local UDP server answers NXDOMAIN after one unrelated packet.
func TestQueryRCodeIgnoresUnrelatedPackets(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := append([]byte{}, buf[:n]...)
		junk := append([]byte{q[0] ^ 0xff, q[1]}, q[2:]...)
		pc.WriteTo(junk, addr)
		r := append([]byte{}, q...)
		binary.BigEndian.PutUint16(r[2:], 0x8183)
		pc.WriteTo(r, addr)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rcode, answers, err := queryRCode(ctx, pc.LocalAddr().String(), "nothing.example.test.")
	if err != nil || rcode != rcodeNXDomain || answers != 0 {
		t.Fatalf("%d %d %v", rcode, answers, err)
	}
}

// udpServer answers every query with the packets reply builds from it (none:
// the server stays silent) and returns its address.
func udpServer(t *testing.T, reply func(q []byte) [][]byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			for _, r := range reply(append([]byte{}, buf[:n]...)) {
				pc.WriteTo(r, addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func withFlags(q []byte, flags uint16) []byte {
	r := append([]byte{}, q...)
	binary.BigEndian.PutUint16(r[2:], flags)
	return r
}

func TestQueryRCodeTruncatedAndOpcodeAreUnknown(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags uint16
		want  error
	}{
		{"truncated-nxdomain", 0x8383, errTruncated},
		{"opcode-status", 0x9183, errOpcode},
	} {
		srv := udpServer(t, func(q []byte) [][]byte { return [][]byte{withFlags(q, tc.flags)} })
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _, err := queryRCode(ctx, srv, "nothing.example.test.")
		cancel()
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

// Packets with another ID never answer the query: with nothing else the
// server's answer is unknown (its deadline), never the stray packet's rcode.
func TestQueryRCodeWrongIDOnlyIsUnknown(t *testing.T) {
	srv := udpServer(t, func(q []byte) [][]byte {
		r := withFlags(q, 0x8183)
		r[0] ^= 0xff
		return [][]byte{r}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, _, err := queryRCode(ctx, srv, "nothing.example.test."); err == nil {
		t.Fatal("a reply with another ID must not be read as an answer")
	}
}

// One silent server gets only its share of the budget; the next still answers.
func TestLookupRCodeGivesEachServerItsShare(t *testing.T) {
	silent := udpServer(t, func([]byte) [][]byte { return nil })
	nx := udpServer(t, func(q []byte) [][]byte { return [][]byte{withFlags(q, 0x8183)} })
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	start := time.Now()
	rcode, _, err := lookupRCode(ctx, []string{silent, silent, nx}, "nothing.example.test.")
	if err != nil || rcode != rcodeNXDomain {
		t.Fatalf("%d %v", rcode, err)
	}
	if d := time.Since(start); d > 850*time.Millisecond {
		t.Fatalf("took %v: the silent servers used the last server's time", d)
	}
}

// A truncated reply from one server is unknown; the next server may answer.
func TestLookupRCodeTruncatedFallsThrough(t *testing.T) {
	tc := udpServer(t, func(q []byte) [][]byte { return [][]byte{withFlags(q, 0x8383)} })
	ok := udpServer(t, func(q []byte) [][]byte { return [][]byte{withFlags(q, 0x8180)} })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := lookupRCode(ctx, []string{tc}, "x.example.test."); !errors.Is(err, errTruncated) {
		t.Fatalf("truncated only: %v", err)
	}
	if rcode, _, err := lookupRCode(ctx, []string{tc, ok}, "x.example.test."); err != nil || rcode != rcodeNoError {
		t.Fatalf("%d %v", rcode, err)
	}
}
