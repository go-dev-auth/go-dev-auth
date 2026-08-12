package fakemongo

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ---- document helpers ----

func lookup(d bson.D, key string) (any, bool) {
	for _, e := range d {
		if e.Key == key {
			return e.Value, true
		}
	}
	return nil, false
}

// lookupPath resolves a possibly dotted field path against a document.
func lookupPath(d bson.D, path string) (any, bool) {
	if !strings.Contains(path, ".") {
		return lookup(d, path)
	}
	var cur any = d
	for _, part := range strings.Split(path, ".") {
		doc, ok := cur.(bson.D)
		if !ok {
			return nil, false
		}
		v, ok := lookup(doc, part)
		if !ok {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

// setField writes a top-level field, appending it if absent, and reports
// whether the stored value actually changed.
func setField(d *bson.D, key string, val any) bool {
	for i := range *d {
		if (*d)[i].Key == key {
			if valuesEqual((*d)[i].Value, val) {
				return false
			}
			(*d)[i].Value = val
			return true
		}
	}
	*d = append(*d, bson.E{Key: key, Value: val})
	return true
}

func unsetField(d *bson.D, key string) bool {
	for i := range *d {
		if (*d)[i].Key == key {
			*d = append((*d)[:i], (*d)[i+1:]...)
			return true
		}
	}
	return false
}

// copyDoc deep-copies a document so stored state can never be aliased by
// a caller (or by a later mutation of a decoded request).
func copyDoc(d bson.D) bson.D {
	out := make(bson.D, len(d))
	for i, e := range d {
		out[i] = bson.E{Key: e.Key, Value: copyValue(e.Value)}
	}
	return out
}

func copyValue(v any) any {
	switch t := v.(type) {
	case bson.D:
		return copyDoc(t)
	case bson.A:
		out := make(bson.A, len(t))
		for i, e := range t {
			out[i] = copyValue(e)
		}
		return out
	case primitive.Binary:
		cp := t
		cp.Data = append([]byte(nil), t.Data...)
		return cp
	case []byte:
		return append([]byte(nil), t...)
	default:
		return v
	}
}

func asDoc(v any) (bson.D, bool) {
	switch t := v.(type) {
	case bson.D:
		return t, true
	case nil:
		return nil, false
	}
	return nil, false
}

func asArray(v any) (bson.A, bool) {
	switch t := v.(type) {
	case bson.A:
		return t, true
	case bson.D:
		// An array encoded as a document with "0", "1", ... keys.
		out := make(bson.A, 0, len(t))
		for _, e := range t {
			out = append(out, e.Value)
		}
		return out, true
	}
	return nil, false
}

func asString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func asBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case int32:
		return t != 0
	case int64:
		return t != 0
	case float64:
		return t != 0
	}
	return false
}

func asInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case int32:
		return int64(t), true
	case int64:
		return t, true
	case float64:
		return int64(t), true
	case primitive.DateTime:
		return int64(t), true
	}
	return 0, false
}

// ---- value comparison ----

// typeRank orders BSON types the way MongoDB's canonical comparison
// order does, so sorts are total even across mixed types.
func typeRank(v any) int {
	switch v.(type) {
	case nil:
		return 1
	case int32, int64, float64:
		return 2
	case string:
		return 3
	case bson.D:
		return 4
	case bson.A:
		return 5
	case primitive.Binary, []byte:
		return 6
	case primitive.ObjectID:
		return 7
	case bool:
		return 8
	case primitive.DateTime:
		return 9
	case primitive.Timestamp:
		return 10
	case primitive.Regex:
		return 11
	}
	return 12
}

func isNumeric(v any) bool {
	switch v.(type) {
	case int32, int64, float64:
		return true
	}
	return false
}

func toFloat(v any) float64 {
	switch t := v.(type) {
	case int32:
		return float64(t)
	case int64:
		return float64(t)
	case float64:
		return t
	}
	return 0
}

func isIntegral(v any) bool {
	switch v.(type) {
	case int32, int64:
		return true
	}
	return false
}

func toInt64(v any) int64 {
	switch t := v.(type) {
	case int32:
		return int64(t)
	case int64:
		return t
	}
	return 0
}

// compareSameKind compares two values of the same type rank.
func compareSameKind(a, b any) int {
	switch {
	case isNumeric(a) && isNumeric(b):
		if isIntegral(a) && isIntegral(b) {
			return cmpInt64(toInt64(a), toInt64(b))
		}
		af, bf := toFloat(a), toFloat(b)
		switch {
		case af < bf:
			return -1
		case af > bf:
			return 1
		}
		return 0
	}
	switch av := a.(type) {
	case nil:
		return 0
	case string:
		bv, _ := b.(string)
		return strings.Compare(av, bv)
	case bool:
		bv, _ := b.(bool)
		switch {
		case av == bv:
			return 0
		case !av:
			return -1
		}
		return 1
	case primitive.DateTime:
		bv, _ := b.(primitive.DateTime)
		return cmpInt64(int64(av), int64(bv))
	case primitive.Timestamp:
		bv, _ := b.(primitive.Timestamp)
		if c := cmpInt64(int64(av.T), int64(bv.T)); c != 0 {
			return c
		}
		return cmpInt64(int64(av.I), int64(bv.I))
	case primitive.ObjectID:
		bv, _ := b.(primitive.ObjectID)
		return strings.Compare(av.Hex(), bv.Hex())
	}
	return 0
}

func cmpInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// compareForQuery compares two values for $gt/$gte/$lt/$lte. MongoDB
// only compares within a type bracket, so a cross-type comparison
// reports "not comparable" and the predicate does not match.
func compareForQuery(a, b any) (int, bool) {
	if isNumeric(a) && isNumeric(b) {
		return compareSameKind(a, b), true
	}
	if typeRank(a) != typeRank(b) {
		return 0, false
	}
	return compareSameKind(a, b), true
}

// compareForSort is a total order used by sort specs; unlike queries it
// falls back to the type rank so mixed types never compare equal.
func compareForSort(a, b any) int {
	if isNumeric(a) && isNumeric(b) {
		return compareSameKind(a, b)
	}
	ra, rb := typeRank(a), typeRank(b)
	if ra != rb {
		return cmpInt64(int64(ra), int64(rb))
	}
	return compareSameKind(a, b)
}

func valuesEqual(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if isNumeric(a) && isNumeric(b) {
		return compareSameKind(a, b) == 0
	}
	if typeRank(a) != typeRank(b) {
		return false
	}
	switch av := a.(type) {
	case bson.D:
		bv, _ := b.(bson.D)
		return docsEqual(av, bv)
	case bson.A:
		bv, _ := b.(bson.A)
		if len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !valuesEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	case primitive.Binary:
		bv, _ := b.(primitive.Binary)
		return av.Subtype == bv.Subtype && string(av.Data) == string(bv.Data)
	case primitive.Regex:
		bv, _ := b.(primitive.Regex)
		return av.Pattern == bv.Pattern && av.Options == bv.Options
	}
	return compareSameKind(a, b) == 0
}

func docsEqual(a, b bson.D) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Key != b[i].Key || !valuesEqual(a[i].Value, b[i].Value) {
			return false
		}
	}
	return true
}

// ---- matching ----

// matchDoc reports whether doc satisfies filter.
func matchDoc(doc bson.D, filter bson.D) bool {
	for _, e := range filter {
		switch e.Key {
		case "$and":
			subs, ok := asArray(e.Value)
			if !ok {
				return false
			}
			for _, sub := range subs {
				sd, ok := asDoc(sub)
				if !ok || !matchDoc(doc, sd) {
					return false
				}
			}
		case "$or":
			subs, ok := asArray(e.Value)
			if !ok {
				return false
			}
			hit := false
			for _, sub := range subs {
				if sd, ok := asDoc(sub); ok && matchDoc(doc, sd) {
					hit = true
					break
				}
			}
			if !hit {
				return false
			}
		case "$nor":
			subs, ok := asArray(e.Value)
			if !ok {
				return false
			}
			for _, sub := range subs {
				if sd, ok := asDoc(sub); ok && matchDoc(doc, sd) {
					return false
				}
			}
		case "$comment":
			// ignored
		default:
			if strings.HasPrefix(e.Key, "$") {
				return false // unsupported top-level operator matches nothing
			}
			v, present := lookupPath(doc, e.Key)
			if !matchField(v, present, e.Value) {
				return false
			}
		}
	}
	return true
}

// isOperatorDoc reports whether cond is a {$op: ...} document rather than
// a literal value to compare for equality.
func isOperatorDoc(cond any) (bson.D, bool) {
	d, ok := asDoc(cond)
	if !ok || len(d) == 0 {
		return nil, false
	}
	for _, e := range d {
		if !strings.HasPrefix(e.Key, "$") {
			return nil, false
		}
	}
	return d, true
}

func matchField(v any, present bool, cond any) bool {
	ops, ok := isOperatorDoc(cond)
	if !ok {
		if re, isRegex := cond.(primitive.Regex); isRegex {
			return present && matchRegex(v, re.Pattern, re.Options)
		}
		if !present {
			return cond == nil // a missing field equals null
		}
		return valuesEqual(v, cond)
	}
	// $regex and $options travel together.
	var regexOptions string
	for _, e := range ops {
		if e.Key == "$options" {
			regexOptions, _ = asString(e.Value)
		}
	}
	for _, e := range ops {
		switch e.Key {
		case "$options":
			continue
		case "$eq":
			if present {
				if !valuesEqual(v, e.Value) {
					return false
				}
			} else if e.Value != nil {
				return false
			}
		case "$ne":
			// MongoDB's $ne also matches documents where the field is
			// absent; the adapter's compare-and-set relies on that.
			if present && valuesEqual(v, e.Value) {
				return false
			}
			if !present && e.Value == nil {
				return false
			}
		case "$gt", "$gte", "$lt", "$lte":
			if !present {
				return false
			}
			c, comparable := compareForQuery(v, e.Value)
			if !comparable {
				return false
			}
			switch e.Key {
			case "$gt":
				if c <= 0 {
					return false
				}
			case "$gte":
				if c < 0 {
					return false
				}
			case "$lt":
				if c >= 0 {
					return false
				}
			case "$lte":
				if c > 0 {
					return false
				}
			}
		case "$in":
			vals, ok := asArray(e.Value)
			if !ok {
				return false
			}
			hit := false
			for _, want := range vals {
				if re, isRegex := want.(primitive.Regex); isRegex {
					if present && matchRegex(v, re.Pattern, re.Options) {
						hit = true
						break
					}
					continue
				}
				if (present && valuesEqual(v, want)) || (!present && want == nil) {
					hit = true
					break
				}
			}
			if !hit {
				return false
			}
		case "$nin":
			vals, ok := asArray(e.Value)
			if !ok {
				return false
			}
			for _, want := range vals {
				if (present && valuesEqual(v, want)) || (!present && want == nil) {
					return false
				}
			}
		case "$exists":
			if asBool(e.Value) != present {
				return false
			}
		case "$regex":
			if !present {
				return false
			}
			switch pat := e.Value.(type) {
			case primitive.Regex:
				opts := pat.Options
				if opts == "" {
					opts = regexOptions
				}
				if !matchRegex(v, pat.Pattern, opts) {
					return false
				}
			case string:
				if !matchRegex(v, pat, regexOptions) {
					return false
				}
			default:
				return false
			}
		case "$not":
			sub, ok := asDoc(e.Value)
			if !ok {
				return false
			}
			if matchField(v, present, sub) {
				return false
			}
		default:
			// Unknown operator: match nothing rather than silently
			// matching everything.
			return false
		}
	}
	return true
}

func matchRegex(v any, pattern, options string) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	var flags string
	for _, o := range options {
		switch o {
		case 'i':
			flags += "i"
		case 'm':
			flags += "m"
		case 's':
			flags += "s"
		}
	}
	if flags != "" {
		pattern = "(?" + flags + ")" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

// ---- sorting ----

// sortDocs orders docs by a bson.D sort spec (1 ascending, -1
// descending). The sort is stable so equal keys keep insertion order.
func sortDocs(docs []bson.D, spec bson.D) {
	if len(spec) == 0 {
		return
	}
	sort.SliceStable(docs, func(i, j int) bool {
		for _, e := range spec {
			dir := 1
			if n, ok := asInt64(e.Value); ok && n < 0 {
				dir = -1
			}
			a, _ := lookupPath(docs[i], e.Key)
			b, _ := lookupPath(docs[j], e.Key)
			if c := compareForSort(a, b); c != 0 {
				return c*dir < 0
			}
		}
		return false
	})
}

// ---- updates ----

// applyUpdate returns a new document with the update applied and reports
// whether anything actually changed.
func applyUpdate(doc bson.D, upd bson.D, inserting bool) (bson.D, bool, error) {
	hasOperators := false
	for _, e := range upd {
		if strings.HasPrefix(e.Key, "$") {
			hasOperators = true
			break
		}
	}
	if !hasOperators {
		// Replacement document: _id is immutable and carries over.
		out := copyDoc(upd)
		if id, ok := lookup(doc, "_id"); ok {
			if _, has := lookup(out, "_id"); !has {
				out = append(bson.D{{Key: "_id", Value: copyValue(id)}}, out...)
			}
		}
		return out, !docsEqual(doc, out), nil
	}

	out := copyDoc(doc)
	modified := false
	for _, e := range upd {
		fields, ok := asDoc(e.Value)
		if !ok {
			return nil, false, fmt.Errorf("update operator %s must be a document", e.Key)
		}
		switch e.Key {
		case "$set":
			for _, f := range fields {
				if setField(&out, f.Key, copyValue(f.Value)) {
					modified = true
				}
			}
		case "$setOnInsert":
			if !inserting {
				continue
			}
			for _, f := range fields {
				if setField(&out, f.Key, copyValue(f.Value)) {
					modified = true
				}
			}
		case "$unset":
			for _, f := range fields {
				if unsetField(&out, f.Key) {
					modified = true
				}
			}
		case "$inc":
			for _, f := range fields {
				delta := toFloat(f.Value)
				cur, present := lookup(out, f.Key)
				switch {
				case !present:
					setField(&out, f.Key, copyValue(f.Value))
				case isIntegral(cur) && isIntegral(f.Value):
					setField(&out, f.Key, toInt64(cur)+toInt64(f.Value))
				default:
					setField(&out, f.Key, toFloat(cur)+delta)
				}
				modified = true
			}
		default:
			return nil, false, fmt.Errorf("fakemongo: unsupported update operator %q", e.Key)
		}
	}
	return out, modified, nil
}

// docFromQuery seeds an upserted document from the equality conditions of
// a filter, the way MongoDB does.
func docFromQuery(filter bson.D) bson.D {
	out := bson.D{}
	for _, e := range filter {
		if strings.HasPrefix(e.Key, "$") || strings.Contains(e.Key, ".") {
			continue
		}
		if ops, isOps := isOperatorDoc(e.Value); isOps {
			for _, op := range ops {
				if op.Key == "$eq" {
					setField(&out, e.Key, copyValue(op.Value))
				}
			}
			continue
		}
		setField(&out, e.Key, copyValue(e.Value))
	}
	return out
}

// ---- unique index enforcement ----

type duplicateKeyError struct {
	ns    string
	index string
	key   bson.D
}

func (e *duplicateKeyError) Error() string {
	var b strings.Builder
	b.WriteString("E11000 duplicate key error collection: ")
	b.WriteString(e.ns)
	b.WriteString(" index: ")
	b.WriteString(e.index)
	b.WriteString(" dup key: { ")
	for i, kv := range e.key {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s: %v", kv.Key, kv.Value)
	}
	b.WriteString(" }")
	return b.String()
}

// checkUnique enforces every unique index (plus the implicit _id index)
// against candidate. skipIdx is the position of the document being
// replaced, or -1 for an insert.
//
// This is a linear scan, not an index: correctness matters here, speed
// does not.
func (c *collection) checkUnique(ns string, candidate bson.D, skipIdx int) error {
	specs := make([]indexSpec, 0, len(c.indexes)+1)
	specs = append(specs, indexSpec{name: "_id_", keys: bson.D{{Key: "_id", Value: 1}}, unique: true})
	specs = append(specs, c.indexes...)

	for _, spec := range specs {
		if !spec.unique {
			continue
		}
		vals := make([]any, len(spec.keys))
		missing := false
		for i, k := range spec.keys {
			v, ok := lookupPath(candidate, k.Key)
			if !ok || v == nil {
				missing = true
			}
			vals[i] = v
		}
		// A sparse index does not contain documents that are missing the
		// key, so those documents never collide with each other.
		if missing && spec.sparse {
			continue
		}
		for i, existing := range c.docs {
			if i == skipIdx {
				continue
			}
			same := true
			for j, k := range spec.keys {
				ev, _ := lookupPath(existing, k.Key)
				if !valuesEqual(ev, vals[j]) {
					same = false
					break
				}
			}
			if !same {
				continue
			}
			key := make(bson.D, len(spec.keys))
			for j, k := range spec.keys {
				key[j] = bson.E{Key: k.Key, Value: vals[j]}
			}
			return &duplicateKeyError{ns: ns, index: spec.name, key: key}
		}
	}
	return nil
}
