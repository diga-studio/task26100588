package docsign

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func twoSteps() []Step {
	return []Step{
		{Kind: StepApprove, Handler: "alice"},
		{Kind: StepSign, Handler: "bob"},
	}
}

func sealOK(body []byte, signer string, digest [32]byte) ([]byte, error) {
	return []byte(fmt.Sprintf("seal:%s:%x", signer, digest[:4])), nil
}

func mustCreate(t *testing.T, s *Service, docID string, steps []Step, body string) {
	t.Helper()
	if err := s.CreateDocument(docID, steps, []byte(body)); err != nil {
		t.Fatalf("CreateDocument: %v", err)
	}
}

func TestCreateValidation(t *testing.T) {
	s := New()
	if err := s.CreateDocument("d1", []Step{{Kind: StepApprove, Handler: "a"}}, nil); !errors.Is(err, ErrInvalidSteps) {
		t.Fatalf("1 step: want ErrInvalidSteps, got %v", err)
	}
	steps := make([]Step, 11)
	for i := range steps {
		steps[i] = Step{Kind: StepApprove, Handler: fmt.Sprintf("h%d", i)}
	}
	if err := s.CreateDocument("d1", steps, nil); !errors.Is(err, ErrInvalidSteps) {
		t.Fatalf("11 steps: want ErrInvalidSteps, got %v", err)
	}
	if err := s.CreateDocument("d1", []Step{{Kind: StepApprove, Handler: "a"}, {Kind: StepSign}}, nil); !errors.Is(err, ErrInvalidSteps) {
		t.Fatalf("empty handler: want ErrInvalidSteps, got %v", err)
	}
	if err := s.CreateDocument("d1", twoSteps(), make([]byte, MaxBodySize+1)); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("oversize body: want ErrBodyTooLarge, got %v", err)
	}
	mustCreate(t, s, "d1", twoSteps(), "A")
	if err := s.CreateDocument("d1", twoSteps(), []byte("A")); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate create: want ErrAlreadyExists, got %v", err)
	}
}

func TestApproveAdvanceAndComplete(t *testing.T) {
	s := New()
	mustCreate(t, s, "d1", twoSteps(), "A")

	res, err := s.Handle(HandleRequest{RequestID: "r1", DocID: "d1", Round: 1, StepIndex: 0, Operator: "alice"}, nil)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if res.AdvancedTo != 1 || res.Completed {
		t.Fatalf("unexpected result: %+v", res)
	}

	res, err = s.Handle(HandleRequest{RequestID: "r2", DocID: "d1", Round: 1, StepIndex: 1, Operator: "bob"}, sealOK)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !res.Completed || res.AdvancedTo != 2 {
		t.Fatalf("unexpected result: %+v", res)
	}
	wantDigest := sha256.Sum256([]byte("A"))
	if res.BodyDigest != wantDigest {
		t.Fatalf("digest mismatch: got %x want %x", res.BodyDigest, wantDigest)
	}
	if len(res.Attachment) == 0 {
		t.Fatal("sign step must carry attachment")
	}

	snap, err := s.Progress("d1")
	if err != nil {
		t.Fatalf("progress: %v", err)
	}
	if !snap.Completed || snap.CurrentStep != 2 || snap.Round != 1 {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
	if len(snap.History) != 2 {
		t.Fatalf("history len = %d, want 2", len(snap.History))
	}
	for _, rec := range snap.History {
		if rec.BodyDigest != wantDigest {
			t.Fatalf("history digest mismatch: got %x want %x", rec.BodyDigest, wantDigest)
		}
	}
	if snap.History[1].Kind != StepSign || len(snap.History[1].Attachment) == 0 {
		t.Fatalf("sign record missing attachment: %+v", snap.History[1])
	}
}

func TestHandleGuards(t *testing.T) {
	s := New()
	mustCreate(t, s, "d1", twoSteps(), "A")

	if _, err := s.Handle(HandleRequest{RequestID: "x", DocID: "nope", Round: 1, StepIndex: 0, Operator: "alice"}, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := s.Handle(HandleRequest{RequestID: "x", DocID: "d1", Round: 2, StepIndex: 0, Operator: "alice"}, nil); !errors.Is(err, ErrStaleRound) {
		t.Fatalf("future round: want ErrStaleRound, got %v", err)
	}
	if _, err := s.Handle(HandleRequest{RequestID: "x", DocID: "d1", Round: 1, StepIndex: 1, Operator: "bob"}, sealOK); !errors.Is(err, ErrNotCurrentStep) {
		t.Fatalf("skip step: want ErrNotCurrentStep, got %v", err)
	}
	if _, err := s.Handle(HandleRequest{RequestID: "x", DocID: "d1", Round: 1, StepIndex: 0, Operator: "mallory"}, nil); !errors.Is(err, ErrNotHandler) {
		t.Fatalf("wrong operator: want ErrNotHandler, got %v", err)
	}

	// 完成第一步后，旧步骤请求与已完成轮次请求。
	if _, err := s.Handle(HandleRequest{RequestID: "r1", DocID: "d1", Round: 1, StepIndex: 0, Operator: "alice"}, nil); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := s.Handle(HandleRequest{RequestID: "x", DocID: "d1", Round: 1, StepIndex: 0, Operator: "alice"}, nil); !errors.Is(err, ErrNotCurrentStep) {
		t.Fatalf("repeat step: want ErrNotCurrentStep, got %v", err)
	}
	if _, err := s.Handle(HandleRequest{RequestID: "r2", DocID: "d1", Round: 1, StepIndex: 1, Operator: "bob"}, sealOK); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := s.Handle(HandleRequest{RequestID: "x", DocID: "d1", Round: 1, StepIndex: 1, Operator: "bob"}, sealOK); !errors.Is(err, ErrRoundCompleted) {
		t.Fatalf("completed round: want ErrRoundCompleted, got %v", err)
	}
}

func TestReplaceStartsNewRoundAndKeepsHistory(t *testing.T) {
	s := New()
	mustCreate(t, s, "d1", twoSteps(), "A")
	if _, err := s.Handle(HandleRequest{RequestID: "r1", DocID: "d1", Round: 1, StepIndex: 0, Operator: "alice"}, nil); err != nil {
		t.Fatalf("approve: %v", err)
	}

	round, err := s.ReplaceBody("d1", []byte("B"))
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if round != 2 {
		t.Fatalf("round = %d, want 2", round)
	}

	snap, err := s.Progress("d1")
	if err != nil {
		t.Fatalf("progress: %v", err)
	}
	if snap.Round != 2 || snap.CurrentStep != 0 || snap.Completed {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
	if string(snap.Body) != "B" {
		t.Fatalf("body = %q, want B", snap.Body)
	}
	if len(snap.History) != 1 || snap.History[0].Round != 1 {
		t.Fatalf("history not kept: %+v", snap.History)
	}
	if snap.History[0].BodyDigest != sha256.Sum256([]byte("A")) {
		t.Fatal("history digest must match round-1 body")
	}

	// 旧轮次办理必须作废。
	if _, err := s.Handle(HandleRequest{RequestID: "r2", DocID: "d1", Round: 1, StepIndex: 1, Operator: "bob"}, sealOK); !errors.Is(err, ErrStaleRound) {
		t.Fatalf("stale round: want ErrStaleRound, got %v", err)
	}
	// 新轮次从第一步开始。
	if _, err := s.Handle(HandleRequest{RequestID: "r3", DocID: "d1", Round: 2, StepIndex: 0, Operator: "alice"}, nil); err != nil {
		t.Fatalf("new round approve: %v", err)
	}
}

func TestBodyBackAndForthAreDistinctRounds(t *testing.T) {
	s := New()
	mustCreate(t, s, "d1", twoSteps(), "A")
	if _, err := s.Handle(HandleRequest{RequestID: "r1", DocID: "d1", Round: 1, StepIndex: 0, Operator: "alice"}, nil); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := s.ReplaceBody("d1", []byte("B")); err != nil {
		t.Fatalf("replace to B: %v", err)
	}
	round, err := s.ReplaceBody("d1", []byte("A"))
	if err != nil {
		t.Fatalf("replace back to A: %v", err)
	}
	if round != 3 {
		t.Fatalf("round = %d, want 3", round)
	}
	// 第三轮正文虽与第一轮相同，办理结果不能复用。
	snap, _ := s.Progress("d1")
	if snap.CurrentStep != 0 {
		t.Fatalf("current step = %d, want 0", snap.CurrentStep)
	}
	if _, err := s.Handle(HandleRequest{RequestID: "r2", DocID: "d1", Round: 3, StepIndex: 0, Operator: "alice"}, nil); err != nil {
		t.Fatalf("round 3 approve: %v", err)
	}
}

func TestSnapshotIsolation(t *testing.T) {
	s := New()
	mustCreate(t, s, "d1", twoSteps(), "A")
	if _, err := s.Handle(HandleRequest{RequestID: "r1", DocID: "d1", Round: 1, StepIndex: 0, Operator: "alice"}, nil); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := s.Handle(HandleRequest{RequestID: "r2", DocID: "d1", Round: 1, StepIndex: 1, Operator: "bob"}, sealOK); err != nil {
		t.Fatalf("sign: %v", err)
	}
	snap, _ := s.Progress("d1")
	// 调用方修改快照内容不得影响库内状态。
	snap.Body[0] = 'X'
	snap.History[1].Attachment[0] = 'X'
	snap.Steps[0].Handler = "mallory"
	snap2, _ := s.Progress("d1")
	if string(snap2.Body) != "A" {
		t.Fatal("snapshot body mutation leaked into service")
	}
	if snap2.History[1].Attachment[0] == 'X' {
		t.Fatal("snapshot attachment mutation leaked into service")
	}
	if snap2.Steps[0].Handler != "alice" {
		t.Fatal("snapshot steps mutation leaked into service")
	}
}

func TestRequestIDConflict(t *testing.T) {
	s := New()
	mustCreate(t, s, "d1", twoSteps(), "A")
	if _, err := s.Handle(HandleRequest{RequestID: "r1", DocID: "d1", Round: 1, StepIndex: 0, Operator: "alice"}, nil); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// 同一标识用于不同命令。
	if _, err := s.Handle(HandleRequest{RequestID: "r1", DocID: "d1", Round: 1, StepIndex: 1, Operator: "bob"}, sealOK); !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("want ErrRequestConflict, got %v", err)
	}
}

func TestIdempotentSuccessAcrossRounds(t *testing.T) {
	s := New()
	mustCreate(t, s, "d1", twoSteps(), "A")
	first, err := s.Handle(HandleRequest{RequestID: "r1", DocID: "d1", Round: 1, StepIndex: 0, Operator: "alice"}, nil)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	// 推进到下一步后重试：返回原结果，不重复推进。
	again, err := s.Handle(HandleRequest{RequestID: "r1", DocID: "d1", Round: 1, StepIndex: 0, Operator: "alice"}, nil)
	if err != nil {
		t.Fatalf("retry after advance: %v", err)
	}
	if !reflect.DeepEqual(again, first) {
		t.Fatalf("retry result differs: %+v vs %+v", again, first)
	}
	// 换版后重试：仍返回原成功结果。
	if _, err := s.ReplaceBody("d1", []byte("B")); err != nil {
		t.Fatalf("replace: %v", err)
	}
	again, err = s.Handle(HandleRequest{RequestID: "r1", DocID: "d1", Round: 1, StepIndex: 0, Operator: "alice"}, nil)
	if err != nil {
		t.Fatalf("retry after replace: %v", err)
	}
	if !reflect.DeepEqual(again, first) {
		t.Fatalf("retry result differs after replace: %+v vs %+v", again, first)
	}
	snap, _ := s.Progress("d1")
	if snap.Round != 2 || snap.CurrentStep != 0 || len(snap.History) != 1 {
		t.Fatalf("retry must not advance new round: %+v", snap)
	}
}
