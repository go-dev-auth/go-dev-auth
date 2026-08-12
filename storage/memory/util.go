package memory

import "time"

func lessValue(a, b any) bool {
	switch ta := a.(type) {
	case time.Time:
		if tb, ok := b.(time.Time); ok {
			return ta.Before(tb)
		}
	case string:
		if tb, ok := b.(string); ok {
			return ta < tb
		}
	case int:
		if tb, ok := b.(int); ok {
			return ta < tb
		}
	case int64:
		if tb, ok := b.(int64); ok {
			return ta < tb
		}
	case float64:
		if tb, ok := b.(float64); ok {
			return ta < tb
		}
	}
	return false
}

func equalValue(a, b any) bool {
	if ta, ok := a.(time.Time); ok {
		if tb, ok2 := b.(time.Time); ok2 {
			return ta.Equal(tb)
		}
	}
	return a == b
}
