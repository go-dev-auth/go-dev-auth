// Package fakemongo is a TEST DOUBLE for mongod: an in-process TCP
// server that speaks just enough of the MongoDB wire protocol for the
// official Go driver to connect and run the handful of commands the
// mongostore issues, against an in-memory document store.
//
// It exists so that storage/mongostore can be integration-tested in
// CI without a real MongoDB server. It is NOT a MongoDB implementation
// and must never be used for anything other than tests.
//
// # What it deliberately does not do
//
//   - No authentication of any kind (no SCRAM, no x.509, no TLS). Any
//     client is accepted; credentials in the URI are ignored.
//   - No replica sets, no sharding, no mongos. It always advertises
//     itself as a standalone server, so the driver never tries
//     retryable writes, causal consistency or streaming heartbeats.
//   - No transactions. startTransaction/commitTransaction/abortTransaction
//     are unimplemented, so Adapter.Transaction will fail here exactly
//     as it does against a real standalone mongod.
//   - No cursors. Every query result is returned whole in the first
//     batch with cursor id 0; getMore always returns an empty batch.
//   - No real index internals. createIndexes records unique/sparse
//     metadata only, and uniqueness is enforced by a linear scan at
//     write time. Nothing is ever persisted, and nothing is optimised.
//   - No compression, no OP_COMPRESSED, no exhaust/streaming responses,
//     no change streams, no GridFS, no server-side JavaScript.
//   - Only a fragment of the query language ($eq, $ne, $gt, $gte, $lt,
//     $lte, $in, $nin, $regex, $exists and the logical $and/$or/$nor),
//     of the update language ($set, $unset, $inc, $setOnInsert) and of
//     the aggregation pipeline ($match, $skip, $limit, $count and a
//     single-group $group with $sum).
//   - No collation, no text/geo indexes, no array or dotted-path update
//     semantics (dotted paths are readable in filters, not writable in
//     $set).
//   - No durability, no oplog, no $clusterTime, no server sessions
//     beyond echoing ok:1 to endSessions.
//
// # Wire protocol
//
// Responses are always OP_MSG (opcode 2013) with a single kind-0 body
// section. Requests are normally OP_MSG too; the one exception is the
// very first message on each connection, because a driver configured
// without a stable API sends the initial handshake as a legacy
// OP_QUERY on <db>.$cmd (see the "legacy hello" rule in the MongoDB
// handshake specification). That single opcode is decoded so the
// handshake can complete; the reply is still OP_MSG, which the driver
// accepts.
package fakemongo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
)

// Wire protocol opcodes.
const (
	opQuery = 2004
	opMsg   = 2013
)

// OP_MSG flag bits.
const (
	flagChecksumPresent uint32 = 1 << 0
	flagMoreToCome      uint32 = 1 << 1
)

const maxMessageSizeBytes = 48000000

// Server is an in-memory fake mongod listening on a local TCP port.
//
// The zero value is not usable; call Listen or Start.
type Server struct {
	ln     net.Listener
	logger *log.Logger

	mu  sync.Mutex // guards dbs and every document in it
	dbs map[string]map[string]*collection

	nextConnID atomic.Int64
	nextReqID  atomic.Int32

	closeOnce sync.Once
	closed    atomic.Bool
	wg        sync.WaitGroup

	connMu sync.Mutex
	conns  map[net.Conn]struct{}
}

// collection is one in-memory collection: an ordered slice of documents
// plus the index metadata createIndexes recorded for it.
type collection struct {
	docs    []bson.D
	indexes []indexSpec
}

// indexSpec is the only thing this fake remembers about an index. Real
// index structures (B-trees, key ordering, partial filter expressions)
// have no analogue here.
type indexSpec struct {
	name   string
	keys   bson.D
	unique bool
	sparse bool
}

// Start launches a fake server for the duration of the test and returns
// the mongodb:// URI to connect to. The server is shut down through
// t.Cleanup.
func Start(t *testing.T) string {
	t.Helper()
	srv, err := Listen()
	if err != nil {
		t.Fatalf("fakemongo: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv.URI()
}

// Listen starts a fake server on a loopback port chosen by the OS.
// Callers that are not tests use this directly and must call Close.
func Listen() (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	s := &Server{
		ln:     ln,
		logger: log.New(os.Stderr, "fakemongo: ", log.Lmicroseconds),
		dbs:    map[string]map[string]*collection{},
		conns:  map[net.Conn]struct{}{},
	}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

// Addr is the host:port the server listens on.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// URI is the connection string for this server.
func (s *Server) URI() string { return "mongodb://" + s.Addr() }

// Close stops the listener, drops every open connection and waits for
// the handler goroutines to finish.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		_ = s.ln.Close()
		s.connMu.Lock()
		for c := range s.conns {
			_ = c.Close()
		}
		s.connMu.Unlock()
		s.wg.Wait()
	})
}

// logf reports server-side problems. Server goroutines must never call
// t.Fatal (that is only legal on the test goroutine), and must not call
// t.Log either since they can outlive the test, so everything goes to
// stderr.
func (s *Server) logf(format string, args ...any) {
	if s.closed.Load() {
		return // teardown noise
	}
	s.logger.Printf(format, args...)
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if !s.closed.Load() {
				s.logf("accept: %v", err)
			}
			return
		}
		s.connMu.Lock()
		s.conns[conn] = struct{}{}
		s.connMu.Unlock()

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn)
		}()
	}
}

func (s *Server) handleConn(conn net.Conn) {
	connID := s.nextConnID.Add(1)
	defer func() {
		_ = conn.Close()
		s.connMu.Lock()
		delete(s.conns, conn)
		s.connMu.Unlock()
	}()

	header := make([]byte, 16)
	for {
		if _, err := io.ReadFull(conn, header); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !s.closed.Load() {
				s.logf("conn %d: read header: %v", connID, err)
			}
			return
		}
		msgLen := int32(binary.LittleEndian.Uint32(header[0:4]))
		reqID := int32(binary.LittleEndian.Uint32(header[4:8]))
		opCode := int32(binary.LittleEndian.Uint32(header[12:16]))
		if msgLen < 16 || msgLen > maxMessageSizeBytes {
			s.logf("conn %d: bogus message length %d", connID, msgLen)
			return
		}
		body := make([]byte, msgLen-16)
		if _, err := io.ReadFull(conn, body); err != nil {
			if !s.closed.Load() {
				s.logf("conn %d: read body: %v", connID, err)
			}
			return
		}

		var (
			cmd  bson.D
			seqs map[string][]bson.D
			err  error
		)
		switch opCode {
		case opMsg:
			cmd, seqs, err = decodeOpMsg(body)
		case opQuery:
			cmd, err = decodeOpQuery(body)
		default:
			s.logf("conn %d: unsupported opcode %d", connID, opCode)
			return
		}
		if err != nil {
			s.logf("conn %d: decode: %v", connID, err)
			return
		}
		if len(cmd) == 0 {
			s.logf("conn %d: empty command document", connID)
			return
		}

		reply := s.dispatch(connID, cmd, seqs)
		if err := s.writeReply(conn, reqID, reply); err != nil {
			if !s.closed.Load() {
				s.logf("conn %d: write reply: %v", connID, err)
			}
			return
		}
	}
}

func (s *Server) writeReply(conn net.Conn, responseTo int32, doc bson.D) error {
	payload, err := bson.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal reply: %w", err)
	}
	total := 16 + 4 + 1 + len(payload)
	buf := make([]byte, 0, total)
	buf = appendInt32(buf, int32(total))
	buf = appendInt32(buf, s.nextReqID.Add(1))
	buf = appendInt32(buf, responseTo)
	buf = appendInt32(buf, opMsg)
	buf = appendInt32(buf, 0) // flagBits: no checksum, no moreToCome
	buf = append(buf, 0)      // section kind 0: single body document
	buf = append(buf, payload...)
	_, err = conn.Write(buf)
	return err
}

func appendInt32(dst []byte, v int32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	return append(dst, b[:]...)
}

// decodeOpMsg splits an OP_MSG body into its kind-0 body document and
// the kind-1 document sequences keyed by identifier ("documents",
// "updates", "deletes").
func decodeOpMsg(body []byte) (bson.D, map[string][]bson.D, error) {
	if len(body) < 4 {
		return nil, nil, errors.New("OP_MSG: truncated flag bits")
	}
	flags := binary.LittleEndian.Uint32(body[0:4])
	rest := body[4:]
	if flags&flagChecksumPresent != 0 {
		// The trailing CRC-32C is not verified: this is a test double,
		// and the driver never rejects a reply for lacking one.
		if len(rest) < 4 {
			return nil, nil, errors.New("OP_MSG: truncated checksum")
		}
		rest = rest[:len(rest)-4]
	}
	// flagMoreToCome marks a fire-and-forget write. The adapter only
	// issues acknowledged writes, so it never appears; if it ever did,
	// the reply this server sends anyway would simply be ignored.

	var (
		body0 bson.D
		found bool
		seqs  map[string][]bson.D
	)
	for len(rest) > 0 {
		kind := rest[0]
		rest = rest[1:]
		switch kind {
		case 0:
			raw, remainder, err := takeDocument(rest)
			if err != nil {
				return nil, nil, fmt.Errorf("OP_MSG kind 0: %w", err)
			}
			if err := bson.Unmarshal(raw, &body0); err != nil {
				return nil, nil, fmt.Errorf("OP_MSG kind 0: %w", err)
			}
			found = true
			rest = remainder
		case 1:
			if len(rest) < 4 {
				return nil, nil, errors.New("OP_MSG kind 1: truncated size")
			}
			size := int(int32(binary.LittleEndian.Uint32(rest[0:4])))
			if size < 5 || size > len(rest) {
				return nil, nil, fmt.Errorf("OP_MSG kind 1: bad section size %d", size)
			}
			section := rest[4:size]
			rest = rest[size:]

			nul := indexByteIn(section, 0)
			if nul < 0 {
				return nil, nil, errors.New("OP_MSG kind 1: unterminated identifier")
			}
			identifier := string(section[:nul])
			docsBytes := section[nul+1:]
			var docs []bson.D
			for len(docsBytes) > 0 {
				raw, remainder, err := takeDocument(docsBytes)
				if err != nil {
					return nil, nil, fmt.Errorf("OP_MSG kind 1 %q: %w", identifier, err)
				}
				var d bson.D
				if err := bson.Unmarshal(raw, &d); err != nil {
					return nil, nil, fmt.Errorf("OP_MSG kind 1 %q: %w", identifier, err)
				}
				docs = append(docs, d)
				docsBytes = remainder
			}
			if seqs == nil {
				seqs = map[string][]bson.D{}
			}
			seqs[identifier] = append(seqs[identifier], docs...)
		default:
			return nil, nil, fmt.Errorf("OP_MSG: unknown section kind %d", kind)
		}
	}
	if !found {
		return nil, nil, errors.New("OP_MSG: no body section")
	}
	return body0, seqs, nil
}

// decodeOpQuery handles the legacy handshake only: int32 flags, cstring
// fullCollectionName, int32 numberToSkip, int32 numberToReturn, then the
// query document.
func decodeOpQuery(body []byte) (bson.D, error) {
	if len(body) < 4 {
		return nil, errors.New("OP_QUERY: truncated flags")
	}
	rest := body[4:]
	nul := indexByteIn(rest, 0)
	if nul < 0 {
		return nil, errors.New("OP_QUERY: unterminated collection name")
	}
	fullCollection := string(rest[:nul])
	rest = rest[nul+1:]
	if len(rest) < 8 {
		return nil, errors.New("OP_QUERY: truncated skip/return")
	}
	rest = rest[8:]
	raw, _, err := takeDocument(rest)
	if err != nil {
		return nil, fmt.Errorf("OP_QUERY: %w", err)
	}
	var q bson.D
	if err := bson.Unmarshal(raw, &q); err != nil {
		return nil, fmt.Errorf("OP_QUERY: %w", err)
	}
	// A legacy handshake carries no "$db"; derive it from
	// "<db>.$cmd" so the dispatcher sees a uniform command shape.
	if _, ok := lookup(q, "$db"); !ok {
		db := fullCollection
		if i := indexByteIn([]byte(fullCollection), '.'); i >= 0 {
			db = fullCollection[:i]
		}
		q = append(q, bson.E{Key: "$db", Value: db})
	}
	return q, nil
}

func takeDocument(b []byte) (doc []byte, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, errors.New("truncated document length")
	}
	size := int(int32(binary.LittleEndian.Uint32(b[0:4])))
	if size < 5 || size > len(b) {
		return nil, nil, fmt.Errorf("bad document size %d (have %d bytes)", size, len(b))
	}
	return b[:size], b[size:], nil
}

func indexByteIn(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// collectionFor returns the named collection, creating it on first use.
// The caller must hold s.mu.
func (s *Server) collectionFor(db, name string) *collection {
	colls, ok := s.dbs[db]
	if !ok {
		colls = map[string]*collection{}
		s.dbs[db] = colls
	}
	c, ok := colls[name]
	if !ok {
		c = &collection{}
		colls[name] = c
	}
	return c
}
