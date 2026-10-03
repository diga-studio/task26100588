package docflow

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

func twoSteps() []Step {
	return []Step{
		{Kind: StepApprove, Assignee: "alice"},
		{Kind: StepSign, Assignee: "bob"},
	}
}

func TestCreateDocumentValidation(t *testing.T) {
	m := NewManager(nil)

	if err := m.CreateDocument("d1", []Step{{Kind: StepApprove, Assignee: "a"}}, []byte("x")); err != ErrInvalidSteps {
		t.Fatalf("1 step: got %v", err)
	}
	many := make([]Step, 11)
	for i := range many {
		many[i] = Step{Kind: StepApprove, Assignee: fmt.Sprintf("u%d", i)}
	}
	if err := m.CreateDocument("d1", many, []byte("x")); err != ErrInvalidSteps {
		t.Fatalf("11 steps: got %v", err)
	}
	if err := m.CreateDocument("d1", []Step{
		{Kind: StepApprove, Assignee: "a"},
		{Kind: StepSign, Assignee: ""},
	}, []byte("x")); err != ErrInvalidSteps {
		t.Fatalf("empty assignee: got %v", err)
	}
	if err := m.CreateDocument("d1", twoSteps(), make([]byte, MaxBodySize+1)); err != ErrBodyTooLarge {
		t.Fatalf("oversize body: got %v", err)
	}
	if err := m.CreateDocument("d1", twoSteps(), []byte("hello")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := m.CreateDocument("d1", twoSteps(), []byte("hello")); err != ErrDocExists {
		t.Fatalf("duplicate: got %v", err)
	}

	for i := 0; i < MaxDocuments-1; i++ {
		if err := m.CreateDocument(fmt.Sprintf("doc-%d", i), twoSteps(), nil); err != nil {
			t.Fatalf("fill %d: %v", i, err)
		}
	}
	if err := m.CreateDocument("overflow", twoSteps(), nil); err != ErrTooManyDocs {
		t.Fatalf("overflow: got %v", err)
	}
}

func TestReplaceBodyStartsNewRound(t *testing.T) {
	m := NewManager(nil)
	if err := m.CreateDocument("d", twoSteps(), []byte("A")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Act(ActRequest{ReqID: "r1", DocID: "d", Round: 1, Step: 0, Actor: "alice"}); err != nil {
		t.Fatal(err)
	}

	// A -> B -> A: three distinct rounds, no reuse of handling results.
	if err := m.ReplaceBody("d", []byte("B")); err != nil {
		t.Fatal(err)
	}
	if err := m.ReplaceBody("d", []byte("A")); err != nil {
		t.Fatal(err)
	}

	p, err := m.GetProgress("d")
	if err != nil {
		t.Fatal(err)
	}
	if p.Round != 3 || p.CurrentStep != 0 || p.Completed {
		t.Fatalf("progress = %+v", p)
	}
	if len(p.History) != 1 || p.History[0].Round != 1 || p.History[0].Step != 0 {
		t.Fatalf("history = %+v", p.History)
	}
	want := sha256.Sum256([]byte("A"))
	if p.Digest != want || p.History[0].Digest != want {
		t.Fatalf("digest mismatch")
	}

	// Old rounds are stale; the identical body of round 3 must be handled anew.
	if _, err := m.Act(ActRequest{ReqID: "r2", DocID: "d", Round: 1, Step: 1, Actor: "bob"}); err != ErrStaleRound {
		t.Fatalf("stale round: got %v", err)
	}
	if _, err := m.Act(ActRequest{ReqID: "r3", DocID: "d", Round: 3, Step: 0, Actor: "alice"}); err != nil {
		t.Fatalf("round 3 step 0: %v", err)
	}
}

func TestGetProgressUnknownAndIsolation(t *testing.T) {
	m := NewManager(nil)
	if _, err := m.GetProgress("nope"); err != ErrDocNotFound {
		t.Fatalf("got %v", err)
	}
	if err := m.ReplaceBody("nope", []byte("x")); err != ErrDocNotFound {
		t.Fatalf("got %v", err)
	}

	body := []byte("mutable")
	if err := m.CreateDocument("d", twoSteps(), body); err != nil {
		t.Fatal(err)
	}
	body[0] = 'X' // caller mutation must not leak into stored state

	p, err := m.GetProgress("d")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Body, []byte("mutable")) {
		t.Fatalf("body = %q", p.Body)
	}
	p.Body[0] = 'Y' // mutating the snapshot must not leak back
	p2, _ := m.GetProgress("d")
	if !bytes.Equal(p2.Body, []byte("mutable")) {
		t.Fatalf("body after snapshot mutation = %q", p2.Body)
	}
}
