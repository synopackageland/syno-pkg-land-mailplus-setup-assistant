package detect

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strings"
	"time"
)

// Go's resolver reports NXDOMAIN (the name does not exist) and NODATA (the
// name exists without that record type, as an empty non-terminal does) as
// the same IsNotFound error, so the net API alone can never prove that a
// name does not exist. RCodeResolver adds that proof: one query for the name,
// returning only the reply header's rcode and answer count. Only NXDOMAIN is
// proof (NOERROR without answers is also how compact denial, RFC 9824, says a
// name does not exist). A resolver without it leaves "every lookup not
// found" unknown, never missing.
type RCodeResolver interface {
	LookupRCode(ctx context.Context, name string) (rcode, answers int, err error)
}

// DNS reply codes read by the existence check.
const (
	rcodeNoError  = 0
	rcodeNXDomain = 3
)

// systemResolver is the production resolver: Go's resolver plus the rcode
// probe against the nameservers in /etc/resolv.conf (read-only, no writes).
type systemResolver struct {
	*net.Resolver
	resolvConf string
}

var (
	errNoNameserver = errors.New("no nameserver")
	// errTruncated: the reply has the TC bit set. A truncated reply is not
	// trusted, not even its rcode: the answer stays unknown (no TCP retry).
	errTruncated = errors.New("truncated reply")
	// errOpcode: a reply to this query whose opcode is not QUERY.
	errOpcode = errors.New("reply opcode is not QUERY")
	// errUnrelated: a packet that does not answer this query (other ID, not
	// a response, other question); it is ignored, never read as an answer.
	errUnrelated = errors.New("unrelated packet")
)

// rcodeBudget is the overall budget when the caller's context has no deadline.
const rcodeBudget = 5 * time.Second

func (r systemResolver) LookupRCode(ctx context.Context, name string) (int, int, error) {
	servers, err := nameservers(r.resolvConf)
	if err != nil {
		return 0, 0, err
	}
	return lookupRCode(ctx, servers, name)
}

// lookupRCode asks each server in turn until one gives a usable answer. Each
// server gets an equal share of what is left of the overall budget, so one
// slow server cannot use up the time of the ones after it; time a server
// does not use passes on to the rest.
func lookupRCode(ctx context.Context, servers []string, name string) (int, int, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(rcodeBudget)
	}
	var last error = errNoNameserver
	for i, s := range servers {
		share := time.Until(deadline) / time.Duration(len(servers)-i)
		if share <= 0 {
			break
		}
		sctx, cancel := context.WithTimeout(ctx, share)
		rcode, answers, err := queryRCode(sctx, s, name)
		cancel()
		if err == nil && (rcode == rcodeNoError || rcode == rcodeNXDomain) {
			return rcode, answers, nil
		}
		if err == nil {
			err = errors.New("unusable rcode")
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return 0, 0, last
}

// nameservers reads at most three "nameserver" lines, as the C resolver does.
func nameservers(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() && len(out) < 3 {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if ip := net.ParseIP(strings.SplitN(fields[1], "%", 2)[0]); ip != nil {
				out = append(out, net.JoinHostPort(fields[1], "53"))
			}
		}
	}
	if len(out) == 0 {
		return nil, errNoNameserver
	}
	return out, nil
}

// rcodeQuery builds a recursive SOA query for name (class IN).
func rcodeQuery(id uint16, name string) ([]byte, error) {
	q := make([]byte, 12, 12+len(name)+6)
	binary.BigEndian.PutUint16(q[0:], id)
	binary.BigEndian.PutUint16(q[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(q[4:], 1)      // QDCOUNT
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(l) == 0 || len(l) > 63 {
			return nil, errors.New("invalid name")
		}
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 6, 0, 1) // root, QTYPE SOA, QCLASS IN
	return q, nil
}

// rcodeReply checks that reply answers query (same ID, a response, the same
// question) and returns its rcode and answer count. errUnrelated means the
// packet is not an answer to this query; errOpcode and errTruncated mean it
// is one that cannot be trusted, so the answer is unknown.
func rcodeReply(query, reply []byte) (int, int, error) {
	if len(reply) < 12 || reply[0] != query[0] || reply[1] != query[1] || reply[2]&0x80 == 0 {
		return 0, 0, errUnrelated
	}
	if (reply[2]>>3)&0x0f != 0 {
		return 0, 0, errOpcode
	}
	if len(reply) < len(query) || binary.BigEndian.Uint16(reply[4:]) != 1 ||
		!strings.EqualFold(string(reply[12:len(query)]), string(query[12:])) {
		return 0, 0, errUnrelated
	}
	if reply[2]&0x02 != 0 {
		return 0, 0, errTruncated
	}
	return int(reply[3] & 0x0f), int(binary.BigEndian.Uint16(reply[6:])), nil
}

func queryRCode(ctx context.Context, server, name string) (int, int, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, 0, err
	}
	query, err := rcodeQuery(binary.BigEndian.Uint16(b[:]), name)
	if err != nil {
		return 0, 0, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(rcodeBudget)
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(query); err != nil {
		return 0, 0, err
	}
	buf := make([]byte, 1232)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return 0, 0, err
		}
		// Packets that do not answer this query are ignored; a reply to it
		// that cannot be trusted (truncated, not QUERY) ends this server.
		rcode, answers, err := rcodeReply(query, buf[:n])
		if errors.Is(err, errUnrelated) {
			continue
		}
		return rcode, answers, err
	}
}
