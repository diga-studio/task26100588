package docflow

import (
	"crypto/sha256"
	"sync"
)

// Manager keeps all documents in process memory.
type Manager struct {
	mu   sync.Mutex
	docs map[string]*document
	gen  SealGenerator
}

// NewManager creates a Manager. gen is used to produce seal attachments for
// signing steps; it may be nil if no document uses signing steps.
func NewManager(gen SealGenerator) *Manager {
	return &Manager{docs: make(map[string]*document), gen: gen}
}

// CreateDocument registers a new document with fixed serial steps and the
// first body version (round 1).
func (m *Manager) CreateDocument(docID string, steps []Step, body []byte) error {
	if err := validateSteps(steps); err != nil {
		return err
	}
	if len(body) > MaxBodySize {
		return ErrBodyTooLarge
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.docs[docID]; ok {
		return ErrDocExists
	}
	if len(m.docs) >= MaxDocuments {
		return ErrTooManyDocs
	}

	d := &document{
		steps:    append([]Step(nil), steps...),
		round:    1,
		done:     make(map[string]doneEntry),
		inflight: make(map[string]*inflightSeal),
	}
	d.setBody(body)
	m.docs[docID] = d
	return nil
}

// ReplaceBody replaces the pending body and starts a new round; all steps
// must be handled again. Successful records of earlier rounds stay in
// history. Seal generations still running for the old round are discarded
// when they finish.
func (m *Manager) ReplaceBody(docID string, body []byte) error {
	if len(body) > MaxBodySize {
		return ErrBodyTooLarge
	}
	d, err := m.get(docID)
	if err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.round++
	d.setBody(body)
	d.currentStep = 0
	d.completed = false
	return nil
}

// GetProgress returns a consistent snapshot of the document: body, round,
// current step and history all belong to the same moment, and seals still
// being generated never appear as successful.
func (m *Manager) GetProgress(docID string) (Progress, error) {
	d, err := m.get(docID)
	if err != nil {
		return Progress{}, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	p := Progress{
		DocID:       docID,
		Round:       d.round,
		CurrentStep: d.currentStep,
		Completed:   d.completed,
		Body:        append([]byte(nil), d.body...),
		Digest:      d.digest,
		Steps:       append([]Step(nil), d.steps...),
		History:     make([]Record, len(d.history)),
	}
	for i, r := range d.history {
		p.History[i] = r
		p.History[i].Seal = append([]byte(nil), r.Seal...)
	}
	return p, nil
}

func (m *Manager) get(docID string) (*document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.docs[docID]
	if !ok {
		return nil, ErrDocNotFound
	}
	return d, nil
}

func validateSteps(steps []Step) error {
	if len(steps) < 2 || len(steps) > 10 {
		return ErrInvalidSteps
	}
	for _, s := range steps {
		if s.Assignee == "" {
			return ErrInvalidSteps
		}
	}
	return nil
}

// setBody replaces the current body, keeping a private copy so later caller
// mutations cannot affect stored state. Caller must hold d.mu.
func (d *document) setBody(body []byte) {
	d.body = append([]byte(nil), body...)
	d.digest = sha256.Sum256(d.body)
}
