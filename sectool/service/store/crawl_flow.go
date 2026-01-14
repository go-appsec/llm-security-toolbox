package store

import (
	"sync"
)

// CrawlFlowEntry holds a reference to a crawler flow.
type CrawlFlowEntry struct {
	SessionID string // Parent session ID
}

// CrawlFlowStore manages the mapping between crawler flow IDs and their metadata.
// Thread-safe. This store allows unified lookup of flows from both proxy and crawler.
type CrawlFlowStore struct {
	mu   sync.RWMutex
	byID map[string]*CrawlFlowEntry // flow_id -> entry
}

// NewCrawlFlowStore creates a new empty CrawlFlowStore.
func NewCrawlFlowStore() *CrawlFlowStore {
	return &CrawlFlowStore{
		byID: make(map[string]*CrawlFlowEntry),
	}
}

// Register adds a crawler flow to the store.
func (s *CrawlFlowStore) Register(flowID, sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.byID[flowID] = &CrawlFlowEntry{
		SessionID: sessionID,
	}
}

// Lookup retrieves a CrawlFlowEntry by flow_id.
// Returns nil and false if not found.
func (s *CrawlFlowStore) Lookup(flowID string) (*CrawlFlowEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.byID[flowID]
	if !ok {
		return nil, false
	}

	// Return a copy to prevent external modification
	entryCopy := *entry
	return &entryCopy, true
}

// Exists checks if a flow ID exists in the store.
func (s *CrawlFlowStore) Exists(flowID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.byID[flowID]
	return ok
}

// Delete removes a flow by ID.
func (s *CrawlFlowStore) Delete(flowID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, flowID)
}

// RemoveSession removes all flows belonging to a session.
func (s *CrawlFlowStore) RemoveSession(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, entry := range s.byID {
		if entry.SessionID == sessionID {
			delete(s.byID, id)
		}
	}
}

// Count returns the number of flows in the store.
func (s *CrawlFlowStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

// Clear removes all entries from the store.
func (s *CrawlFlowStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID = make(map[string]*CrawlFlowEntry)
}
