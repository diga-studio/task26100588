package docflow

import "sync"

// document is the mutable in-memory state of one managed document.
type document struct {
	mu sync.Mutex

	steps []Step

	round       int
	body        []byte
	digest      [32]byte
	currentStep int
	completed   bool

	history []Record

	// idempotent results of successfully handled requests, by ReqID
	done map[string]doneEntry
	// in-flight seal generations, by ReqID
	inflight map[string]*inflightSeal
}

// doneEntry remembers the command and result of a successful request.
type doneEntry struct {
	req    ActRequest
	result ActResult
}

// inflightSeal coordinates concurrent retries of one signing request so the
// seal is generated exactly once and all waiters share the outcome.
type inflightSeal struct {
	req  ActRequest
	done chan struct{}
	seal []byte
	err  error
}
