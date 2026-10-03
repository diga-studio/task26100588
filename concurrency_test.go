package docsign

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSlowSealVoidedByReplace：签章未返回时连续换版 A->B->A，旧结果作废。
func TestSlowSealVoidedByReplace(t *testing.T) {
	s := New()
	mustCreate(t, s, "d1", twoSteps(), "A")
	if _, err := s.Handle(HandleRequest{RequestID: "r1", DocID: "d1", Round: 1, StepIndex: 0, Operator: "alice"}, nil); err != nil {
		t.Fatalf("approve: %v", err)
	}

	release := make(chan struct{})
	genStarted := make(chan struct{})
	slowGen := func(body []byte, signer string, digest [32]byte) ([]byte, error) {
		close(genStarted)
		<-release
		return []byte("late-seal"), nil
	}
	signDone := make(chan error, 1)
	go func() {
		_, err := s.Handle(HandleRequest{RequestID: "r2", DocID: "d1", Round: 1, StepIndex: 1, Operator: "bob"}, slowGen)
		signDone <- err
	}()
	<-genStarted

	// 签章生成期间连续换版 A->B->A。
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
	close(release)

	if err := <-signDone; !errors.Is(err, ErrStaleRound) {
		t.Fatalf("late seal: want ErrStaleRound, got %v", err)
	}

	snap, err := s.Progress("d1")
	if err != nil {
		t.Fatalf("progress: %v", err)
	}
	if snap.Round != 3 || snap.CurrentStep != 0 || snap.Completed {
		t.Fatalf("new round must restart from step 0: %+v", snap)
	}
	// 旧轮次只有换版前已成功的审批记录，迟到的签章不得补记。
	if len(snap.History) != 1 || snap.History[0].Kind != StepApprove || snap.History[0].Round != 1 {
		t.Fatalf("history: %+v", snap.History)
	}
}

// TestSealBeforeReplaceKeptInHistory：签章先成功再换版，成功保留在旧轮次历史中。
func TestSealBeforeReplaceKeptInHistory(t *testing.T) {
	s := New()
	mustCreate(t, s, "d1", twoSteps(), "A")
	if _, err := s.Handle(HandleRequest{RequestID: "r1", DocID: "d1", Round: 1, StepIndex: 0, Operator: "alice"}, nil); err != nil {
		t.Fatalf("approve: %v", err)
	}
	res, err := s.Handle(HandleRequest{RequestID: "r2", DocID: "d1", Round: 1, StepIndex: 1, Operator: "bob"}, sealOK)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !res.Completed {
		t.Fatal("round 1 should be completed")
	}
	if _, err := s.ReplaceBody("d1", []byte("B")); err != nil {
		t.Fatalf("replace: %v", err)
	}
	snap, err := s.Progress("d1")
	if err != nil {
		t.Fatalf("progress: %v", err)
	}
	if len(snap.History) != 2 {
		t.Fatalf("history len = %d, want 2", len(snap.History))
	}
	signRec := snap.History[1]
	if signRec.Round != 1 || signRec.Kind != StepSign || len(signRec.Attachment) == 0 {
		t.Fatalf("sign record lost: %+v", signRec)
	}
	if signRec.BodyDigest != sha256.Sum256([]byte("A")) {
		t.Fatal("sign digest must match round-1 body A")
	}
}

// TestConcurrentSameRequestSingleGeneration：同一请求并发重试共享一次生成。
func TestConcurrentSameRequestSingleGeneration(t *testing.T) {
	s := New()
	mustCreate(t, s, "d1", twoSteps(), "A")
	if _, err := s.Handle(HandleRequest{RequestID: "r1", DocID: "d1", Round: 1, StepIndex: 0, Operator: "alice"}, nil); err != nil {
		t.Fatalf("approve: %v", err)
	}

	var calls atomic.Int32
	gate := make(chan struct{})
	gen := func(body []byte, signer string, digest [32]byte) ([]byte, error) {
		calls.Add(1)
		<-gate
		return []byte("seal"), nil
	}
	req := HandleRequest{RequestID: "r2", DocID: "d1", Round: 1, StepIndex: 1, Operator: "bob"}
	const n = 8
	results := make([]HandleResult, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = s.Handle(req, gen)
		}(i)
	}
	// 等所有 goroutine 进入等待后放开门闩。
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("generator called %d times, want 1", got)
	}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("retry %d: %v", i, errs[i])
		}
		if results[i].StepIndex != 1 || !results[i].Completed || string(results[i].Attachment) != "seal" {
			t.Fatalf("retry %d result: %+v", i, results[i])
		}
	}
	snap, _ := s.Progress("d1")
	if len(snap.History) != 2 {
		t.Fatalf("history len = %d, want 2 (advance exactly once)", len(snap.History))
	}

	// 成功后跨步骤、跨轮次重试仍返回原结果，且不再触发生成。
	if _, err := s.ReplaceBody("d1", []byte("B")); err != nil {
		t.Fatalf("replace: %v", err)
	}
	again, err := s.Handle(req, gen)
	if err != nil {
		t.Fatalf("cross-round retry: %v", err)
	}
	if string(again.Attachment) != "seal" || !again.Completed {
		t.Fatalf("cross-round retry result: %+v", again)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("generator called %d times after retry, want 1", got)
	}
	snap, _ = s.Progress("d1")
	if snap.Round != 2 || snap.CurrentStep != 0 {
		t.Fatalf("retry must not advance new round: %+v", snap)
	}
}

// TestConcurrentDifferentRequestsSameStep：不同请求竞争同一步，最多一个成功。
func TestConcurrentDifferentRequestsSameStep(t *testing.T) {
	s := New()
	mustCreate(t, s, "d1", twoSteps(), "A")
	if _, err := s.Handle(HandleRequest{RequestID: "r1", DocID: "d1", Round: 1, StepIndex: 0, Operator: "alice"}, nil); err != nil {
		t.Fatalf("approve: %v", err)
	}

	gate := make(chan struct{})
	gen := func(body []byte, signer string, digest [32]byte) ([]byte, error) {
		<-gate
		return []byte("seal-" + signer), nil
	}
	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := HandleRequest{RequestID: fmt.Sprintf("req-%d", i), DocID: "d1", Round: 1, StepIndex: 1, Operator: "bob"}
			_, errs[i] = s.Handle(req, gen)
		}(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()

	succeeded := 0
	for i, err := range errs {
		if err == nil {
			succeeded++
		} else if !errors.Is(err, ErrStepBusy) && !errors.Is(err, ErrNotCurrentStep) {
			t.Fatalf("request %d: unexpected error %v", i, err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d requests succeeded, want exactly 1", succeeded)
	}
	snap, _ := s.Progress("d1")
	signCount := 0
	for _, rec := range snap.History {
		if rec.Kind == StepSign {
			signCount++
		}
	}
	if signCount != 1 {
		t.Fatalf("%d sign records, want exactly 1", signCount)
	}
}

// TestGenerationFailureThenRetry：生成失败不推进，可用原请求标识重试成功。
func TestGenerationFailureThenRetry(t *testing.T) {
	s := New()
	mustCreate(t, s, "d1", twoSteps(), "A")
	if _, err := s.Handle(HandleRequest{RequestID: "r1", DocID: "d1", Round: 1, StepIndex: 0, Operator: "alice"}, nil); err != nil {
		t.Fatalf("approve: %v", err)
	}

	genErr := errors.New("seal service unavailable")
	var calls atomic.Int32
	gen := func(body []byte, signer string, digest [32]byte) ([]byte, error) {
		if calls.Add(1) == 1 {
			return nil, genErr
		}
		return []byte("seal"), nil
	}
	req := HandleRequest{RequestID: "r2", DocID: "d1", Round: 1, StepIndex: 1, Operator: "bob"}
	if _, err := s.Handle(req, gen); !errors.Is(err, genErr) {
		t.Fatalf("want generation error, got %v", err)
	}
	snap, _ := s.Progress("d1")
	if snap.CurrentStep != 1 || len(snap.History) != 1 {
		t.Fatalf("failure must not advance: %+v", snap)
	}
	// 原请求标识重试成功。
	res, err := s.Handle(req, gen)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !res.Completed || string(res.Attachment) != "seal" {
		t.Fatalf("retry result: %+v", res)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("generator called %d times, want 2", got)
	}
}

// TestSlowSealDoesNotBlockOthers：慢签章期间其他操作在 200ms 内完成。
func TestSlowSealDoesNotBlockOthers(t *testing.T) {
	s := New()
	mustCreate(t, s, "d1", twoSteps(), "A")
	mustCreate(t, s, "d2", twoSteps(), "X")
	if _, err := s.Handle(HandleRequest{RequestID: "r1", DocID: "d1", Round: 1, StepIndex: 0, Operator: "alice"}, nil); err != nil {
		t.Fatalf("approve: %v", err)
	}

	genStarted := make(chan struct{})
	release := make(chan struct{})
	slowGen := func(body []byte, signer string, digest [32]byte) ([]byte, error) {
		close(genStarted)
		<-release
		return []byte("slow-seal"), nil
	}
	signDone := make(chan error, 1)
	go func() {
		_, err := s.Handle(HandleRequest{RequestID: "r2", DocID: "d1", Round: 1, StepIndex: 1, Operator: "bob"}, slowGen)
		signDone <- err
	}()
	<-genStarted

	const limit = 200 * time.Millisecond
	check := func(name string, fn func()) {
		t.Helper()
		start := time.Now()
		fn()
		if d := time.Since(start); d > limit {
			t.Fatalf("%s took %v, exceeds %v", name, d, limit)
		}
	}
	check("ReplaceBody", func() {
		if _, err := s.ReplaceBody("d1", []byte("B")); err != nil {
			t.Fatalf("replace: %v", err)
		}
	})
	check("Progress", func() {
		snap, err := s.Progress("d1")
		if err != nil {
			t.Fatalf("progress: %v", err)
		}
		// 生成中的签章不得显示为成功。
		if snap.Round != 2 || snap.CurrentStep != 0 {
			t.Fatalf("snapshot inconsistent: %+v", snap)
		}
		for _, rec := range snap.History {
			if rec.Kind == StepSign {
				t.Fatal("in-flight seal must not appear as success")
			}
		}
	})
	check("HandleOtherDoc", func() {
		if _, err := s.Handle(HandleRequest{RequestID: "r3", DocID: "d2", Round: 1, StepIndex: 0, Operator: "alice"}, nil); err != nil {
			t.Fatalf("approve d2: %v", err)
		}
	})
	close(release)
	if err := <-signDone; !errors.Is(err, ErrStaleRound) {
		t.Fatalf("late seal: want ErrStaleRound, got %v", err)
	}
}

// TestHistoryDigestsMatchRoundBodies：历史中每个成功签署的摘要与所属轮次正文一致。
func TestHistoryDigestsMatchRoundBodies(t *testing.T) {
	s := New()
	steps := []Step{
		{Kind: StepSign, Handler: "bob"},
		{Kind: StepApprove, Handler: "alice"},
	}
	mustCreate(t, s, "d1", steps, "A")
	bodies := []string{"A", "B", "A"}
	for round := 1; round <= 3; round++ {
		if round > 1 {
			if _, err := s.ReplaceBody("d1", []byte(bodies[round-1])); err != nil {
				t.Fatalf("replace round %d: %v", round, err)
			}
		}
		if _, err := s.Handle(HandleRequest{RequestID: fmt.Sprintf("sign-%d", round), DocID: "d1", Round: round, StepIndex: 0, Operator: "bob"}, sealOK); err != nil {
			t.Fatalf("sign round %d: %v", round, err)
		}
		if _, err := s.Handle(HandleRequest{RequestID: fmt.Sprintf("appr-%d", round), DocID: "d1", Round: round, StepIndex: 1, Operator: "alice"}, nil); err != nil {
			t.Fatalf("approve round %d: %v", round, err)
		}
	}
	snap, err := s.Progress("d1")
	if err != nil {
		t.Fatalf("progress: %v", err)
	}
	if len(snap.History) != 6 {
		t.Fatalf("history len = %d, want 6", len(snap.History))
	}
	for _, rec := range snap.History {
		want := sha256.Sum256([]byte(bodies[rec.Round-1]))
		if rec.BodyDigest != want {
			t.Fatalf("round %d step %d: digest %x, want %x", rec.Round, rec.StepIndex, rec.BodyDigest, want)
		}
	}
}
