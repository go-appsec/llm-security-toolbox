package store

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrawlFlowStore(t *testing.T) {
	t.Parallel()

	t.Run("register_and_lookup", func(t *testing.T) {
		store := NewCrawlFlowStore()

		store.Register("flow1", "session1")

		entry, ok := store.Lookup("flow1")
		require.True(t, ok)
		assert.Equal(t, "session1", entry.SessionID)
	})

	t.Run("lookup_not_found", func(t *testing.T) {
		store := NewCrawlFlowStore()

		entry, ok := store.Lookup("nonexistent")
		assert.False(t, ok)
		assert.Nil(t, entry)
	})

	t.Run("lookup_returns_copy", func(t *testing.T) {
		store := NewCrawlFlowStore()
		store.Register("flow1", "session1")

		entry1, _ := store.Lookup("flow1")
		entry1.SessionID = "modified"

		entry2, _ := store.Lookup("flow1")
		assert.Equal(t, "session1", entry2.SessionID)
	})

	t.Run("exists", func(t *testing.T) {
		store := NewCrawlFlowStore()

		assert.False(t, store.Exists("flow1"))

		store.Register("flow1", "session1")
		assert.True(t, store.Exists("flow1"))
	})

	t.Run("delete", func(t *testing.T) {
		store := NewCrawlFlowStore()
		store.Register("flow1", "session1")
		store.Register("flow2", "session1")

		store.Delete("flow1")

		assert.False(t, store.Exists("flow1"))
		assert.True(t, store.Exists("flow2"))
	})

	t.Run("remove_session", func(t *testing.T) {
		store := NewCrawlFlowStore()
		store.Register("flow1", "session1")
		store.Register("flow2", "session1")
		store.Register("flow3", "session2")

		store.RemoveSession("session1")

		assert.False(t, store.Exists("flow1"))
		assert.False(t, store.Exists("flow2"))
		assert.True(t, store.Exists("flow3"))
	})

	t.Run("count", func(t *testing.T) {
		store := NewCrawlFlowStore()

		assert.Equal(t, 0, store.Count())

		store.Register("flow1", "session1")
		assert.Equal(t, 1, store.Count())

		store.Register("flow2", "session1")
		assert.Equal(t, 2, store.Count())

		store.Register("flow1", "session2") // overwrite
		assert.Equal(t, 2, store.Count())
	})

	t.Run("clear", func(t *testing.T) {
		store := NewCrawlFlowStore()
		store.Register("flow1", "session1")
		store.Register("flow2", "session1")
		store.Register("flow3", "session2")

		assert.Equal(t, 3, store.Count())

		store.Clear()

		assert.Equal(t, 0, store.Count())
		assert.False(t, store.Exists("flow1"))
	})
}

func TestCrawlFlowStoreConcurrency(t *testing.T) {
	t.Parallel()

	store := NewCrawlFlowStore()
	var wg sync.WaitGroup

	// Concurrent registrations
	for i := range 100 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			flowID := "flow" + string(rune('0'+n%10))
			store.Register(flowID, "session1")
		}(i)
	}

	// Concurrent lookups
	for i := range 100 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			flowID := "flow" + string(rune('0'+n%10))
			store.Lookup(flowID)
			store.Exists(flowID)
		}(i)
	}

	// Concurrent counts
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.Count()
		}()
	}

	wg.Wait()

	// Final state check - should have 10 unique flows
	assert.LessOrEqual(t, store.Count(), 10)
}
