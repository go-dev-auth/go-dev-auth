package storage

import (
	"reflect"
	"strings"
	"time"
)

func equal(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if ta, ok := a.(time.Time); ok {
		if tb, ok2 := b.(time.Time); ok2 {
			return ta.Equal(tb)
		}
	}
	if na, ok := toFloat(a); ok {
		if nb, ok2 := toFloat(b); ok2 {
			return na == nb
		}
	}
	return reflect.DeepEqual(a, b)
}

func compare(a, b any, op Operator) bool {
	if ta, ok := a.(time.Time); ok {
		tb, ok2 := b.(time.Time)
		if !ok2 {
			return false
		}
		switch op {
		case OpGt:
			return ta.After(tb)
		case OpGte:
			return ta.After(tb) || ta.Equal(tb)
		case OpLt:
			return ta.Before(tb)
		case OpLte:
			return ta.Before(tb) || ta.Equal(tb)
		}
		return false
	}
	na, ok := toFloat(a)
	nb, ok2 := toFloat(b)
	if ok && ok2 {
		switch op {
		case OpGt:
			return na > nb
		case OpGte:
			return na >= nb
		case OpLt:
			return na < nb
		case OpLte:
			return na <= nb
		}
		return false
	}
	sa, sok := a.(string)
	sb, sok2 := b.(string)
	if sok && sok2 {
		switch op {
		case OpGt:
			return sa > sb
		case OpGte:
			return sa >= sb
		case OpLt:
			return sa < sb
		case OpLte:
			return sa <= sb
		}
	}
	return false
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case int:
		return float64(t), true
	case int32:
		return float64(t), true
	case int64:
		return float64(t), true
	case float32:
		return float64(t), true
	case float64:
		return t, true
	}
	return 0, false
}

func anySlice(v any) ([]any, bool) {
	if v == nil {
		return nil, false
	}
	if s, ok := v.([]any); ok {
		return s, true
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice {
		return nil, false
	}
	out := make([]any, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		out[i] = rv.Index(i).Interface()
	}
	return out, true
}

// Substring matching is case-insensitive on every adapter; see the
// note in sqlstore.buildWhere for why the contract is defined that
// way rather than left to each database's default collation.
func strContains(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

func strHasPrefix(s, p string) bool {
	return strings.HasPrefix(strings.ToLower(s), strings.ToLower(p))
}

func strHasSuffix(s, suf string) bool {
	return strings.HasSuffix(strings.ToLower(s), strings.ToLower(suf))
}
