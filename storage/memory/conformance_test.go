package memory_test

import (
	"testing"

	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
	"github.com/go-dev-auth/go-dev-auth/storage/storagetest"
)

// TestConformance runs the shared adapter contract against the
// in-memory storage.
func TestConformance(t *testing.T) {
	storagetest.Run(t, func(t *testing.T) (storage.Adapter, func()) {
		store := memory.New()
		store.SetSchema(storagetest.Schema())
		return store, func() {}
	})
}
