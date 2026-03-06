package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// PendingRequest represents an HTTP request waiting for phone approval.
type PendingRequest struct {
	ID           string
	Domain       string
	Method       string
	URL          string
	Path         string
	CreatedAt    time.Time
	ResultCh     chan struct{}
	Result       ApprovalResult
	once         sync.Once
	WaiterCount  int32 // atomic
}

// Resolve sets the result and closes the channel so all waiters unblock.
func (pr *PendingRequest) Resolve(result ApprovalResult) {
	pr.once.Do(func() {
		pr.Result = result
		close(pr.ResultCh)
	})
}

// Wait blocks until the request is resolved and returns the result.
func (pr *PendingRequest) Wait() ApprovalResult {
	<-pr.ResultCh
	return pr.Result
}

// ApprovalResult is sent on the PendingRequest channel when approval is received.
type ApprovalResult struct {
	Approved       bool
	Grant          *Grant
	Error          error
	ConfigApproved *bool
}

// PendingRequestStore is a thread-safe store for pending requests awaiting approval.
type PendingRequestStore struct {
	mu       sync.Mutex
	requests map[string]*PendingRequest
}

// NewPendingRequestStore creates a new PendingRequestStore.
func NewPendingRequestStore() *PendingRequestStore {
	return &PendingRequestStore{
		requests: make(map[string]*PendingRequest),
	}
}

// Add registers a pending request.
func (s *PendingRequestStore) Add(pr *PendingRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[pr.ID] = pr
}

// Remove deletes a pending request by ID only if WaiterCount has reached 0.
func (s *PendingRequestStore) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pr, ok := s.requests[id]
	if !ok {
		return
	}
	if atomic.LoadInt32(&pr.WaiterCount) <= 0 {
		delete(s.requests, id)
	}
}

// Get retrieves a pending request by ID.
func (s *PendingRequestStore) Get(id string) *PendingRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests[id]
}

// FindByDomain returns the first pending request matching the given domain.
func (s *PendingRequestStore) FindByDomain(domain string) *PendingRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pr := range s.requests {
		if pr.Domain == domain {
			return pr
		}
	}
	return nil
}

// List returns all pending requests.
func (s *PendingRequestStore) List() []*PendingRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]*PendingRequest, 0, len(s.requests))
	for _, pr := range s.requests {
		result = append(result, pr)
	}
	return result
}

// Resolve sends an ApprovalResult on the request's channel and removes it from the store.
// If the request does not exist, this is a no-op.
func (s *PendingRequestStore) Resolve(id string, result ApprovalResult) {
	s.mu.Lock()
	pr, ok := s.requests[id]
	if !ok {
		s.mu.Unlock()
		return
	}
	delete(s.requests, id)
	s.mu.Unlock()

	pr.Resolve(result)
}
