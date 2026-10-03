package docflow

import "errors"

var (
	ErrDocNotFound     = errors.New("docflow: document not found")
	ErrDocExists       = errors.New("docflow: document already exists")
	ErrTooManyDocs     = errors.New("docflow: document limit reached")
	ErrInvalidSteps    = errors.New("docflow: steps must be 2..10 with non-empty assignees")
	ErrBodyTooLarge    = errors.New("docflow: body exceeds 1MiB")
	ErrStaleRound      = errors.New("docflow: target round is no longer current")
	ErrStaleStep       = errors.New("docflow: target step is not the current step")
	ErrNotAssignee     = errors.New("docflow: actor is not the assignee of this step")
	ErrRoundCompleted  = errors.New("docflow: document round already completed")
	ErrRequestConflict = errors.New("docflow: request id reused for a different command")
	ErrSealDiscarded   = errors.New("docflow: seal generation finished after the round was replaced")
)

const MaxBodySize = 1 << 20 // 1MiB

const MaxDocuments = 100

// StepKind distinguishes approval steps from signing steps.
type StepKind int

const (
	StepApprove StepKind = iota
	StepSign
)

// Step is one serial step of a document's workflow.
type Step struct {
	Kind     StepKind
	Assignee string
}

// SealGenerator produces a seal attachment for a signing step. It receives the
// target round's body, the signer, and the SHA-256 digest of that body.
type SealGenerator func(body []byte, signer string, digest [32]byte) ([]byte, error)

// Record is one successful handling of a step, kept in history forever.
type Record struct {
	Round  int
	Step   int
	Kind   StepKind
	Actor  string
	Digest [32]byte // SHA-256 of the round body this record belongs to
	Seal   []byte   // nil for approval steps
	ReqID  string
}

// Progress is a consistent snapshot of a document at one moment.
type Progress struct {
	DocID       string
	Round       int
	CurrentStep int  // index into Steps; == len(Steps) when the round completed
	Completed   bool // current round finished all steps
	Body        []byte
	Digest      [32]byte
	Steps       []Step
	History     []Record // successful records of all rounds, in completion order
}

// ActRequest is one handling command issued by the caller.
type ActRequest struct {
	ReqID string
	DocID string
	Round int
	Step  int
	Actor string
}

// ActResult is the outcome of a successful Act call.
type ActResult struct {
	Round     int
	Step      int
	Kind      StepKind
	Seal      []byte // nil for approval steps
	Digest    [32]byte
	Completed bool // whether this act finished the whole round
}
