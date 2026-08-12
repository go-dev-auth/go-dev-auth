package fakemongo

import (
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Server error codes used by this fake.
const (
	codeDuplicateKey    int32 = 11000
	codeCommandNotFound int32 = 59
	codeFailedToParse   int32 = 9
)

func okReply(extra ...bson.E) bson.D {
	out := make(bson.D, 0, len(extra)+1)
	out = append(out, extra...)
	return append(out, bson.E{Key: "ok", Value: float64(1)})
}

func errReply(code int32, codeName, format string, args ...any) bson.D {
	return bson.D{
		{Key: "ok", Value: float64(0)},
		{Key: "errmsg", Value: fmt.Sprintf(format, args...)},
		{Key: "code", Value: code},
		{Key: "codeName", Value: codeName},
	}
}

// dispatch routes one command document to its handler. Every handler
// runs under s.mu, so the whole server behaves as if it had a single
// global write lock — plenty for a test double, and it makes the
// concurrent-insert conformance case deterministic.
func (s *Server) dispatch(connID int64, cmd bson.D, seqs map[string][]bson.D) bson.D {
	name := cmd[0].Key
	arg := cmd[0].Value
	db, _ := asString(valueOr(cmd, "$db", "test"))

	switch strings.ToLower(name) {
	case "hello", "ismaster":
		return s.hello(connID)
	case "ping":
		return okReply()
	case "buildinfo":
		return okReply(
			bson.E{Key: "version", Value: "7.0.0"},
			bson.E{Key: "versionArray", Value: bson.A{int32(7), int32(0), int32(0), int32(0)}},
			bson.E{Key: "gitVersion", Value: "fakemongo"},
			bson.E{Key: "maxBsonObjectSize", Value: int32(16777216)},
			bson.E{Key: "bits", Value: int32(64)},
			bson.E{Key: "debug", Value: false},
		)
	case "getparameter":
		return okReply()
	case "endsessions", "refreshsessions", "getlasterror":
		return okReply(bson.E{Key: "n", Value: int32(0)})
	case "killcursors":
		return okReply(
			bson.E{Key: "cursorsKilled", Value: bson.A{}},
			bson.E{Key: "cursorsNotFound", Value: bson.A{}},
			bson.E{Key: "cursorsAlive", Value: bson.A{}},
			bson.E{Key: "cursorsUnknown", Value: bson.A{}},
		)
	case "getmore":
		return s.getMore(db, cmd)
	case "insert":
		return s.insert(db, arg, cmd, seqs)
	case "find":
		return s.find(db, arg, cmd)
	case "update":
		return s.update(db, arg, cmd, seqs)
	case "delete":
		return s.delete(db, arg, cmd, seqs)
	case "findandmodify":
		return s.findAndModify(db, arg, cmd)
	case "aggregate":
		return s.aggregate(db, arg, cmd)
	case "createindexes":
		return s.createIndexes(db, arg, cmd)
	case "listindexes":
		return s.listIndexes(db, arg)
	case "dropindexes":
		return okReply(bson.E{Key: "nIndexesWas", Value: int32(1)})
	case "create":
		return s.createCollection(db, arg)
	case "drop":
		return s.drop(db, arg)
	case "dropdatabase":
		return s.dropDatabase(db)
	case "listcollections":
		return s.listCollections(db)
	default:
		return errReply(codeCommandNotFound, "CommandNotFound", "no such command: %s", name)
	}
}

func valueOr(d bson.D, key string, fallback any) any {
	if v, ok := lookup(d, key); ok {
		return v
	}
	return fallback
}

// hello answers the handshake. Getting these fields right is what lets
// the driver finish topology discovery and mark the server selectable.
// No "msg", no "setName" and no "isreplicaset" means standalone.
func (s *Server) hello(connID int64) bson.D {
	return bson.D{
		{Key: "helloOk", Value: true},
		{Key: "ismaster", Value: true},
		{Key: "isWritablePrimary", Value: true},
		{Key: "maxBsonObjectSize", Value: int32(16777216)},
		{Key: "maxMessageSizeBytes", Value: int32(maxMessageSizeBytes)},
		{Key: "maxWriteBatchSize", Value: int32(100000)},
		{Key: "localTime", Value: primitive.NewDateTimeFromTime(time.Now())},
		{Key: "logicalSessionTimeoutMinutes", Value: int32(30)},
		{Key: "connectionId", Value: int32(connID)},
		{Key: "minWireVersion", Value: int32(0)},
		{Key: "maxWireVersion", Value: int32(21)},
		{Key: "readOnly", Value: false},
		{Key: "ok", Value: float64(1)},
	}
}

// ---- reads ----

func cursorReply(ns string, batchKey string, docs bson.A) bson.D {
	return okReply(bson.E{Key: "cursor", Value: bson.D{
		{Key: "id", Value: int64(0)}, // 0 = exhausted, so getMore is never needed
		{Key: "ns", Value: ns},
		{Key: batchKey, Value: docs},
	}})
}

func (s *Server) getMore(db string, cmd bson.D) bson.D {
	coll, _ := asString(valueOr(cmd, "collection", "unknown"))
	return cursorReply(db+"."+coll, "nextBatch", bson.A{})
}

// selectDocs applies filter/sort/skip/limit and returns deep copies.
// The caller must hold s.mu.
func (c *collection) selectDocs(filter, sortSpec bson.D, skip, limit int64) []bson.D {
	var matched []bson.D
	for _, d := range c.docs {
		if matchDoc(d, filter) {
			matched = append(matched, d)
		}
	}
	sortDocs(matched, sortSpec)
	if skip > 0 {
		if skip >= int64(len(matched)) {
			return nil
		}
		matched = matched[skip:]
	}
	if limit > 0 && limit < int64(len(matched)) {
		matched = matched[:limit]
	}
	out := make([]bson.D, len(matched))
	for i, d := range matched {
		out[i] = copyDoc(d)
	}
	return out
}

func (s *Server) find(db string, arg any, cmd bson.D) bson.D {
	coll, ok := asString(arg)
	if !ok {
		return errReply(codeFailedToParse, "FailedToParse", "find: collection name must be a string")
	}
	filter, _ := asDoc(valueOr(cmd, "filter", bson.D{}))
	sortSpec, _ := asDoc(valueOr(cmd, "sort", bson.D{}))
	skip, _ := asInt64(valueOr(cmd, "skip", int64(0)))
	limit, _ := asInt64(valueOr(cmd, "limit", int64(0)))
	if limit < 0 {
		// A negative limit means "one batch of |limit| documents".
		limit = -limit
	}
	// "projection" is deliberately ignored: the adapter never uses one,
	// and honouring it would only hide bugs.

	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.collectionFor(db, coll)
	docs := c.selectDocs(filter, sortSpec, skip, limit)

	batch := make(bson.A, len(docs))
	for i, d := range docs {
		batch[i] = d
	}
	return cursorReply(db+"."+coll, "firstBatch", batch)
}

func (s *Server) aggregate(db string, arg any, cmd bson.D) bson.D {
	coll, ok := asString(arg)
	if !ok {
		// aggregate: 1 is a database-level aggregation; nothing to do.
		return cursorReply(db+".$cmd.aggregate", "firstBatch", bson.A{})
	}
	stages, _ := asArray(valueOr(cmd, "pipeline", bson.A{}))

	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.collectionFor(db, coll)

	docs := make([]bson.D, 0, len(c.docs))
	for _, d := range c.docs {
		docs = append(docs, copyDoc(d))
	}

	for _, raw := range stages {
		stage, ok := asDoc(raw)
		if !ok || len(stage) == 0 {
			return errReply(codeFailedToParse, "FailedToParse", "aggregate: malformed pipeline stage")
		}
		op, spec := stage[0].Key, stage[0].Value
		switch op {
		case "$match":
			filter, _ := asDoc(spec)
			kept := docs[:0]
			for _, d := range docs {
				if matchDoc(d, filter) {
					kept = append(kept, d)
				}
			}
			docs = kept
		case "$sort":
			sortSpec, _ := asDoc(spec)
			sortDocs(docs, sortSpec)
		case "$skip":
			n, _ := asInt64(spec)
			if n >= int64(len(docs)) {
				docs = nil
			} else if n > 0 {
				docs = docs[n:]
			}
		case "$limit":
			n, _ := asInt64(spec)
			if n >= 0 && n < int64(len(docs)) {
				docs = docs[:n]
			}
		case "$count":
			field, _ := asString(spec)
			if field == "" {
				field = "count"
			}
			docs = []bson.D{{{Key: field, Value: int64(len(docs))}}}
		case "$group":
			grouped, err := groupStage(docs, spec)
			if err != nil {
				return errReply(codeFailedToParse, "FailedToParse", "%s", err.Error())
			}
			docs = grouped
		default:
			return errReply(codeFailedToParse, "FailedToParse",
				"fakemongo: unsupported aggregation stage %q", op)
		}
	}

	batch := make(bson.A, len(docs))
	for i, d := range docs {
		batch[i] = d
	}
	return cursorReply(db+"."+coll, "firstBatch", batch)
}

// groupStage implements just enough of $group for CountDocuments, which
// sends {$group: {_id: 1, n: {$sum: 1}}}: a constant _id (one group) and
// $sum accumulators over a literal or a field reference.
func groupStage(docs []bson.D, spec any) ([]bson.D, error) {
	group, ok := asDoc(spec)
	if !ok {
		return nil, fmt.Errorf("$group must be a document")
	}
	idVal, hasID := lookup(group, "_id")
	if !hasID {
		return nil, fmt.Errorf("$group requires an _id")
	}
	if ref, isStr := idVal.(string); isStr && strings.HasPrefix(ref, "$") {
		return nil, fmt.Errorf("fakemongo: $group by field expression %q is not supported", ref)
	}

	out := bson.D{{Key: "_id", Value: copyValue(idVal)}}
	for _, acc := range group {
		if acc.Key == "_id" {
			continue
		}
		accDoc, ok := asDoc(acc.Value)
		if !ok || len(accDoc) != 1 {
			return nil, fmt.Errorf("fakemongo: unsupported accumulator for %q", acc.Key)
		}
		if accDoc[0].Key != "$sum" {
			return nil, fmt.Errorf("fakemongo: unsupported accumulator %q", accDoc[0].Key)
		}
		operand := accDoc[0].Value
		if ref, isStr := operand.(string); isStr && strings.HasPrefix(ref, "$") {
			field := strings.TrimPrefix(ref, "$")
			var total float64
			integral := true
			for _, d := range docs {
				v, _ := lookupPath(d, field)
				if !isNumeric(v) {
					continue
				}
				if !isIntegral(v) {
					integral = false
				}
				total += toFloat(v)
			}
			if integral {
				out = append(out, bson.E{Key: acc.Key, Value: int64(total)})
			} else {
				out = append(out, bson.E{Key: acc.Key, Value: total})
			}
			continue
		}
		// Literal operand: {$sum: 1} counts documents.
		out = append(out, bson.E{Key: acc.Key, Value: int64(len(docs)) * toInt64OrOne(operand)})
	}
	if len(docs) == 0 {
		// An empty input produces no groups at all, matching MongoDB.
		return nil, nil
	}
	return []bson.D{out}, nil
}

func toInt64OrOne(v any) int64 {
	if n, ok := asInt64(v); ok {
		return n
	}
	return 1
}

// ---- writes ----

// sequenceOrArray reads a batch that may have arrived either as an
// OP_MSG kind-1 document sequence or inline in the body document.
func sequenceOrArray(cmd bson.D, seqs map[string][]bson.D, key string) []bson.D {
	if docs, ok := seqs[key]; ok {
		return docs
	}
	arr, ok := asArray(valueOr(cmd, key, nil))
	if !ok {
		return nil
	}
	out := make([]bson.D, 0, len(arr))
	for _, v := range arr {
		if d, ok := asDoc(v); ok {
			out = append(out, d)
		}
	}
	return out
}

func writeErrorDoc(index int, code int32, msg string) bson.D {
	return bson.D{
		{Key: "index", Value: int32(index)},
		{Key: "code", Value: code},
		{Key: "errmsg", Value: msg},
	}
}

func (s *Server) insert(db string, arg any, cmd bson.D, seqs map[string][]bson.D) bson.D {
	coll, ok := asString(arg)
	if !ok {
		return errReply(codeFailedToParse, "FailedToParse", "insert: collection name must be a string")
	}
	docs := sequenceOrArray(cmd, seqs, "documents")
	ordered := true
	if v, ok := lookup(cmd, "ordered"); ok {
		ordered = asBool(v)
	}
	ns := db + "." + coll

	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.collectionFor(db, coll)

	n := 0
	var writeErrors bson.A
	for i, d := range docs {
		candidate := copyDoc(d)
		if err := c.checkUnique(ns, candidate, -1); err != nil {
			writeErrors = append(writeErrors, writeErrorDoc(i, codeDuplicateKey, err.Error()))
			if ordered {
				break
			}
			continue
		}
		c.docs = append(c.docs, candidate)
		n++
	}

	reply := okReply(bson.E{Key: "n", Value: int32(n)})
	if len(writeErrors) > 0 {
		reply = append(reply, bson.E{Key: "writeErrors", Value: writeErrors})
	}
	return reply
}

func (s *Server) update(db string, arg any, cmd bson.D, seqs map[string][]bson.D) bson.D {
	coll, ok := asString(arg)
	if !ok {
		return errReply(codeFailedToParse, "FailedToParse", "update: collection name must be a string")
	}
	updates := sequenceOrArray(cmd, seqs, "updates")
	ordered := true
	if v, ok := lookup(cmd, "ordered"); ok {
		ordered = asBool(v)
	}
	ns := db + "." + coll

	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.collectionFor(db, coll)

	var (
		matchedTotal  int
		modifiedTotal int
		writeErrors   bson.A
		upserted      bson.A
	)

statements:
	for i, u := range updates {
		filter, _ := asDoc(valueOr(u, "q", bson.D{}))
		spec, _ := asDoc(valueOr(u, "u", bson.D{}))
		multi := asBool(valueOr(u, "multi", false))
		upsert := asBool(valueOr(u, "upsert", false))

		var targets []int
		for idx, d := range c.docs {
			if matchDoc(d, filter) {
				targets = append(targets, idx)
				if !multi {
					break
				}
			}
		}

		if len(targets) == 0 {
			if !upsert {
				continue
			}
			seed := docFromQuery(filter)
			newDoc, _, err := applyUpdate(seed, spec, true)
			if err != nil {
				writeErrors = append(writeErrors, writeErrorDoc(i, codeFailedToParse, err.Error()))
				if ordered {
					break statements
				}
				continue
			}
			if _, has := lookup(newDoc, "_id"); !has {
				newDoc = append(bson.D{{Key: "_id", Value: primitive.NewObjectID()}}, newDoc...)
			}
			if err := c.checkUnique(ns, newDoc, -1); err != nil {
				writeErrors = append(writeErrors, writeErrorDoc(i, codeDuplicateKey, err.Error()))
				if ordered {
					break statements
				}
				continue
			}
			c.docs = append(c.docs, newDoc)
			id, _ := lookup(newDoc, "_id")
			upserted = append(upserted, bson.D{
				{Key: "index", Value: int32(i)},
				{Key: "_id", Value: id},
			})
			matchedTotal++ // MongoDB reports an upsert in n
			continue
		}

		for _, idx := range targets {
			newDoc, changed, err := applyUpdate(c.docs[idx], spec, false)
			if err != nil {
				writeErrors = append(writeErrors, writeErrorDoc(i, codeFailedToParse, err.Error()))
				if ordered {
					break statements
				}
				continue
			}
			if err := c.checkUnique(ns, newDoc, idx); err != nil {
				writeErrors = append(writeErrors, writeErrorDoc(i, codeDuplicateKey, err.Error()))
				if ordered {
					break statements
				}
				continue
			}
			c.docs[idx] = newDoc
			matchedTotal++
			if changed {
				modifiedTotal++
			}
		}
	}

	// "n" is the MATCHED count, not the modified count: the adapter's
	// compare-and-set depends on that distinction.
	reply := okReply(
		bson.E{Key: "n", Value: int32(matchedTotal)},
		bson.E{Key: "nModified", Value: int32(modifiedTotal)},
	)
	if len(upserted) > 0 {
		reply = append(reply, bson.E{Key: "upserted", Value: upserted})
	}
	if len(writeErrors) > 0 {
		reply = append(reply, bson.E{Key: "writeErrors", Value: writeErrors})
	}
	return reply
}

func (s *Server) delete(db string, arg any, cmd bson.D, seqs map[string][]bson.D) bson.D {
	coll, ok := asString(arg)
	if !ok {
		return errReply(codeFailedToParse, "FailedToParse", "delete: collection name must be a string")
	}
	deletes := sequenceOrArray(cmd, seqs, "deletes")

	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.collectionFor(db, coll)

	total := 0
	for _, del := range deletes {
		filter, _ := asDoc(valueOr(del, "q", bson.D{}))
		// limit 0 deletes every match; limit 1 deletes a single one.
		limit, _ := asInt64(valueOr(del, "limit", int64(0)))

		removed := int64(0)
		kept := make([]bson.D, 0, len(c.docs))
		for _, d := range c.docs {
			if (limit == 0 || removed < limit) && matchDoc(d, filter) {
				removed++
				continue
			}
			kept = append(kept, d)
		}
		c.docs = kept
		total += int(removed)
	}
	return okReply(bson.E{Key: "n", Value: int32(total)})
}

func (s *Server) findAndModify(db string, arg any, cmd bson.D) bson.D {
	coll, ok := asString(arg)
	if !ok {
		return errReply(codeFailedToParse, "FailedToParse", "findAndModify: collection name must be a string")
	}
	filter, _ := asDoc(valueOr(cmd, "query", bson.D{}))
	sortSpec, _ := asDoc(valueOr(cmd, "sort", bson.D{}))
	spec, _ := asDoc(valueOr(cmd, "update", nil))
	returnNew := asBool(valueOr(cmd, "new", false))
	upsert := asBool(valueOr(cmd, "upsert", false))
	remove := asBool(valueOr(cmd, "remove", false))
	ns := db + "." + coll

	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.collectionFor(db, coll)

	// Find the target honouring the sort spec, then map back to its
	// position in the store.
	target := -1
	if len(sortSpec) == 0 {
		for idx, d := range c.docs {
			if matchDoc(d, filter) {
				target = idx
				break
			}
		}
	} else {
		type candidate struct {
			idx int
			doc bson.D
		}
		var cands []candidate
		for idx, d := range c.docs {
			if matchDoc(d, filter) {
				cands = append(cands, candidate{idx, d})
			}
		}
		if len(cands) > 0 {
			ordered := make([]bson.D, len(cands))
			for i, cd := range cands {
				ordered[i] = cd.doc
			}
			sortDocs(ordered, sortSpec)
			// ordered[0] is the winner; map it back to its slot.
			for _, cd := range cands {
				if docsEqual(cd.doc, ordered[0]) {
					target = cd.idx
					break
				}
			}
		}
	}

	if target < 0 {
		if !upsert {
			return okReply(
				bson.E{Key: "lastErrorObject", Value: bson.D{
					{Key: "n", Value: int32(0)},
					{Key: "updatedExisting", Value: false},
				}},
				// BSON null, so the driver reports ErrNoDocuments.
				bson.E{Key: "value", Value: nil},
			)
		}
		seed := docFromQuery(filter)
		newDoc, _, err := applyUpdate(seed, spec, true)
		if err != nil {
			return errReply(codeFailedToParse, "FailedToParse", "%s", err.Error())
		}
		if _, has := lookup(newDoc, "_id"); !has {
			newDoc = append(bson.D{{Key: "_id", Value: primitive.NewObjectID()}}, newDoc...)
		}
		if err := c.checkUnique(ns, newDoc, -1); err != nil {
			return errReply(codeDuplicateKey, "DuplicateKey", "%s", err.Error())
		}
		c.docs = append(c.docs, newDoc)
		id, _ := lookup(newDoc, "_id")
		var value any
		if returnNew {
			value = copyDoc(newDoc)
		}
		return okReply(
			bson.E{Key: "lastErrorObject", Value: bson.D{
				{Key: "n", Value: int32(1)},
				{Key: "updatedExisting", Value: false},
				{Key: "upserted", Value: id},
			}},
			bson.E{Key: "value", Value: value},
		)
	}

	old := copyDoc(c.docs[target])
	if remove {
		c.docs = append(c.docs[:target], c.docs[target+1:]...)
		return okReply(
			bson.E{Key: "lastErrorObject", Value: bson.D{
				{Key: "n", Value: int32(1)},
				{Key: "updatedExisting", Value: false},
			}},
			bson.E{Key: "value", Value: old},
		)
	}

	newDoc, _, err := applyUpdate(c.docs[target], spec, false)
	if err != nil {
		return errReply(codeFailedToParse, "FailedToParse", "%s", err.Error())
	}
	// findAndModify reports a duplicate key as a command error rather
	// than a writeErrors array, which is what mongo.IsDuplicateKeyError
	// looks for on this path.
	if err := c.checkUnique(ns, newDoc, target); err != nil {
		return errReply(codeDuplicateKey, "DuplicateKey", "%s", err.Error())
	}
	c.docs[target] = newDoc

	value := old
	if returnNew {
		value = copyDoc(newDoc)
	}
	return okReply(
		bson.E{Key: "lastErrorObject", Value: bson.D{
			{Key: "n", Value: int32(1)},
			{Key: "updatedExisting", Value: true},
		}},
		bson.E{Key: "value", Value: value},
	)
}

// ---- indexes and collections ----

func (s *Server) createIndexes(db string, arg any, cmd bson.D) bson.D {
	coll, ok := asString(arg)
	if !ok {
		return errReply(codeFailedToParse, "FailedToParse", "createIndexes: collection name must be a string")
	}
	specs, _ := asArray(valueOr(cmd, "indexes", bson.A{}))

	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.collectionFor(db, coll)

	before := int32(len(c.indexes) + 1) // +1 for the implicit _id index
	for _, raw := range specs {
		spec, ok := asDoc(raw)
		if !ok {
			continue
		}
		keys, _ := asDoc(valueOr(spec, "key", bson.D{}))
		name, _ := asString(valueOr(spec, "name", ""))
		if name == "" {
			parts := make([]string, 0, len(keys))
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s_%v", k.Key, k.Value))
			}
			name = strings.Join(parts, "_")
		}
		exists := false
		for _, existing := range c.indexes {
			if existing.name == name {
				exists = true
				break
			}
		}
		if exists {
			continue
		}
		c.indexes = append(c.indexes, indexSpec{
			name:   name,
			keys:   copyDoc(keys),
			unique: asBool(valueOr(spec, "unique", false)),
			sparse: asBool(valueOr(spec, "sparse", false)),
		})
	}
	after := int32(len(c.indexes) + 1)

	return okReply(
		bson.E{Key: "createdCollectionAutomatically", Value: false},
		bson.E{Key: "numIndexesBefore", Value: before},
		bson.E{Key: "numIndexesAfter", Value: after},
	)
}

func (s *Server) listIndexes(db string, arg any) bson.D {
	coll, _ := asString(arg)
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.collectionFor(db, coll)

	batch := bson.A{bson.D{
		{Key: "v", Value: int32(2)},
		{Key: "key", Value: bson.D{{Key: "_id", Value: int32(1)}}},
		{Key: "name", Value: "_id_"},
	}}
	for _, idx := range c.indexes {
		entry := bson.D{
			{Key: "v", Value: int32(2)},
			{Key: "key", Value: copyDoc(idx.keys)},
			{Key: "name", Value: idx.name},
		}
		if idx.unique {
			entry = append(entry, bson.E{Key: "unique", Value: true})
		}
		if idx.sparse {
			entry = append(entry, bson.E{Key: "sparse", Value: true})
		}
		batch = append(batch, entry)
	}
	return cursorReply(db+"."+coll, "firstBatch", batch)
}

func (s *Server) createCollection(db string, arg any) bson.D {
	coll, ok := asString(arg)
	if !ok {
		return errReply(codeFailedToParse, "FailedToParse", "create: collection name must be a string")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.collectionFor(db, coll)
	return okReply()
}

func (s *Server) drop(db string, arg any) bson.D {
	coll, ok := asString(arg)
	if !ok {
		return errReply(codeFailedToParse, "FailedToParse", "drop: collection name must be a string")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if colls, ok := s.dbs[db]; ok {
		delete(colls, coll)
	}
	return okReply(bson.E{Key: "nIndexesWas", Value: int32(1)}, bson.E{Key: "ns", Value: db + "." + coll})
}

func (s *Server) dropDatabase(db string) bson.D {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.dbs, db)
	return okReply(bson.E{Key: "dropped", Value: db})
}

func (s *Server) listCollections(db string) bson.D {
	s.mu.Lock()
	defer s.mu.Unlock()
	batch := bson.A{}
	for name := range s.dbs[db] {
		batch = append(batch, bson.D{
			{Key: "name", Value: name},
			{Key: "type", Value: "collection"},
		})
	}
	return cursorReply(db+".$cmd.listCollections", "firstBatch", batch)
}
