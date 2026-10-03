package docflow

import (
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func signSteps() []Step {
	return []Step{
		{Kind: StepApprove, Assignee: "alice"},
		{Kind: StepSign, Assignee: "bob"},
	}
}

func fastGen(body []byte, signer string, digest [32]byte) ([]byte, error) {
	return append([]byte("seal:"), body...), nil
}

func TestSerialOrderAssigneeAndCompletion(t *testing.T) {
	m := NewManager(fastGen)
	if err := m.CreateDocument("d", signSteps(), []byte("A")); err != nil {
		t.Fatal(err)
	}

	// Cannot handle a later step ahead of time.
	if _, err := m.Act(ActRequest{ReqID: "s1", DocID: "d", Round: 1, Step: 1, Actor: "bob"}); err != ErrStaleStep {
		t.Fatalf("skip step: got %v", err)
	}
	// Only the assignee may handle the step.
	if _, err := m.Act(ActRequest{ReqID: "s2", DocID: "d", Round: 1, Step: 0, Actor: "mallory"}); err != ErrNotAssignee {
		t.Fatalf("wrong actor: got %v", err)
	}
	if _, err := m.Act(ActRequest{ReqID: "s3", DocID: "d", Round: 1, Step: 0, Actor: "alice"}); err != nil {
		t.Fatal(err)
	}
	res, err := m.Act(ActRequest{ReqID: "s4", DocID: "d", Round: 1, Step: 1, Actor: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Completed || string(res.Seal) != "seal:A" {
		t.Fatalf("res = %+v", res)
	}
	if _, err := m.Act(ActRequest{ReqID: "s5", DocID: "d", Round: 1, Step: 2, Actor: "bob"}); err != ErrRoundCompleted {
		t.Fatalf("after completion: got %v", err)
	}

	p, _ := m.GetProgress("d")
	if !p.Completed || p.CurrentStep != 2 || len(p.History) != 2 {
		t.Fatalf("progress = %+v", p)
	}
}

func TestSealDiscardedWhenReplacedDuringGeneration(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	var startedOnce sync.Once
	gen := func(body []byte, signer string, digest [32]byte) ([]byte, error) {
		startedOnce.Do(func() { close(started) })
		<-release
		return []byte("late-seal"), nil
	}
	m := NewManager(gen)
	if err := m.CreateDocument("d", signSteps(), []byte("A")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Act(ActRequest{ReqID: "a1", DocID: "d", Round: 1, Step: 0, Actor: "alice"}); err != nil {
		t.Fatal(err)
	}

	signDone := make(chan error, 1)
	go func() {
		_, err := m.Act(ActRequest{ReqID: "g1", DocID: "d", Round: 1, Step: 1, Actor: "bob"})
		signDone <- err
	}()

	// Body goes A -> B -> A while the round-1 seal is still generating.
	<-started
	if err := m.ReplaceBody("d", []byte("B")); err != nil {
		t.Fatal(err)
	}
	if err := m.ReplaceBody("d", []byte("A")); err != nil {
		t.Fatal(err)
	}
	close(release)

	if err := <-signDone; err != ErrSealDiscarded {
		t.Fatalf("late seal: got %v", err)
	}

	p, _ := m.GetProgress("d")
	if p.Round != 3 || p.CurrentStep != 0 || p.Completed {
		t.Fatalf("progress = %+v", p)
	}
	// Only the round-1 approval survives; the late seal is nowhere.
	if len(p.History) != 1 || p.History[0].Kind != StepApprove || p.History[0].Round != 1 {
		t.Fatalf("history = %+v", p.History)
	}

	// Round 3 has the same body "A" but must be handled from step 0 again.
	if _, err := m.Act(ActRequest{ReqID: "a2", DocID: "d", Round: 3, Step: 0, Actor: "alice"}); err != nil {
		t.Fatal(err)
	}
	res, err := m.Act(ActRequest{ReqID: "g2", DocID: "d", Round: 3, Step: 1, Actor: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Round != 3 || !res.Completed {
		t.Fatalf("res = %+v", res)
	}
}

func TestSealSuccessThenReplaceKeepsOldRoundHistory(t *testing.T) {
	m := NewManager(fastGen)
	if err := m.CreateDocument("d", signSteps(), []byte("A")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Act(ActRequest{ReqID: "a1", DocID: "d", Round: 1, Step: 0, Actor: "alice"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Act(ActRequest{ReqID: "g1", DocID: "d", Round: 1, Step: 1, Actor: "bob"}); err != nil {
		t.Fatal(err)
	}
	if err := m.ReplaceBody("d", []byte("B")); err != nil {
		t.Fatal(err)
	}

	p, _ := m.GetProgress("d")
	if p.Round != 2 || p.CurrentStep != 0 || len(p.History) != 2 {
		t.Fatalf("progress = %+v", p)
	}
	want := sha256.Sum256([]byte("A"))
	for _, r := range p.History {
		if r.Round != 1 || r.Digest != want {
			t.Fatalf("record = %+v", r)
		}
	}
	if string(p.History[1].Seal) != "seal:A" {
		t.Fatalf("seal = %q", p.History[1].Seal)
	}
}

func TestConcurrentDuplicateAndDistinctRequests(t *testing.T) {
	var genCalls atomic.Int32
	gen := func(body []byte, signer string, digest [32]byte) ([]byte, error) {
		genCalls.Add(1)
		time.Sleep(50 * time.Millisecond)
		return []byte("seal"), nil
	}
	m := NewManager(gen)
	if err := m.CreateDocument("d", signSteps(), []byte("A")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Act(ActRequest{ReqID: "a1", DocID: "d", Round: 1, Step: 0, Actor: "alice"}); err != nil {
		t.Fatal(err)
	}

	// Duplicates of one request: exactly one generation, all share the result.
	const dup = 8
	var wg sync.WaitGroup
	errs := make([]error, dup)
	results := make([]ActResult, dup)
	for i := 0; i < dup; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = m.Act(ActRequest{ReqID: "dup", DocID: "d", Round: 1, Step: 1, Actor: "bob"})
		}(i)
	}
	wg.Wait()
	for i := 0; i < dup; i++ {
		if errs[i] != nil {
			t.Fatalf("duplicate %d: %v", i, errs[i])
		}
		if !results[i].Completed || string(results[i].Seal) != "seal" {
			t.Fatalf("duplicate %d result = %+v", i, results[i])
		}
	}
	if n := genCalls.Load(); n != 1 {
		t.Fatalf("generations for one request = %d", n)
	}

	// Distinct requests racing on a fresh sign step: exactly one succeeds.
	if err := m.ReplaceBody("d", []byte("B")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Act(ActRequest{ReqID: "a2", DocID: "d", Round: 2, Step: 0, Actor: "alice"}); err != nil {
		t.Fatal(err)
	}
	const racers = 6
	var wg2 sync.WaitGroup
	var successes atomic.Int32
	for i := 0; i < racers; i++ {
		wg2.Add(1)
		go func(i int) {
			defer wg2.Done()
			_, err := m.Act(ActRequest{ReqID: string(rune('a' + i)), DocID: "d", Round: 2, Step: 1, Actor: "bob"})
			if err == nil {
				successes.Add(1)
			} else if err != ErrSealDiscarded && err != ErrStaleStep {
				t.Errorf("unexpected error: %v", err)
			}
		}(i)
	}
	wg2.Wait()
	if n := successes.Load(); n != 1 {
		t.Fatalf("successes = %d", n)
	}
	p, _ := m.GetProgress("d")
	signs := 0
	for _, r := range p.History {
		if r.Round == 2 && r.Kind == StepSign {
			signs++
		}
	}
	if signs != 1 {
		t.Fatalf("round-2 seals in history = %d", signs)
	}
}

func TestIdempotentReplayAcrossStepsAndRounds(t *testing.T) {
	var genCalls atomic.Int32
	gen := func(body []byte, signer string, digest [32]byte) ([]byte, error) {
		genCalls.Add(1)
		return []byte("seal:" + string(body)), nil
	}
	m := NewManager(gen)
	if err := m.CreateDocument("d", signSteps(), []byte("A")); err != nil {
		t.Fatal(err)
	}
	req := ActRequest{ReqID: "g1", DocID: "d", Round: 1, Step: 1, Actor: "bob"}
	if _, err := m.Act(ActRequest{ReqID: "a1", DocID: "d", Round: 1, Step: 0, Actor: "alice"}); err != nil {
		t.Fatal(err)
	}
	first, err := m.Act(req)
	if err != nil {
		t.Fatal(err)
	}

	// Replay after the workflow moved on and after a replacement: the
	// original result comes back, no new generation, no further advance.
	if err := m.ReplaceBody("d", []byte("B")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		again, err := m.Act(req)
		if err != nil {
			t.Fatal(err)
		}
		if again.Round != first.Round || string(again.Seal) != "seal:A" || !again.Completed {
			t.Fatalf("replay = %+v", again)
		}
	}
	if n := genCalls.Load(); n != 1 {
		t.Fatalf("generations = %d", n)
	}
	p, _ := m.GetProgress("d")
	if p.Round != 2 || p.CurrentStep != 0 || len(p.History) != 2 {
		t.Fatalf("progress = %+v", p)
	}

	// Same request id for a different command is rejected.
	if _, err := m.Act(ActRequest{ReqID: "g1", DocID: "d", Round: 2, Step: 0, Actor: "alice"}); err != ErrRequestConflict {
		t.Fatalf("conflict: got %v", err)
	}
}

func TestGenerationFailureThenRetry(t *testing.T) {
	var calls atomic.Int32
	boom := errors.New("seal service unavailable")
	gen := func(body []byte, signer string, digest [32]byte) ([]byte, error) {
		if calls.Add(1) == 1 {
			return nil, boom
		}
		return []byte("seal"), nil
	}
	m := NewManager(gen)
	if err := m.CreateDocument("d", signSteps(), []byte("A")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Act(ActRequest{ReqID: "a1", DocID: "d", Round: 1, Step: 0, Actor: "alice"}); err != nil {
		t.Fatal(err)
	}

	req := ActRequest{ReqID: "g1", DocID: "d", Round: 1, Step: 1, Actor: "bob"}
	if _, err := m.Act(req); !errors.Is(err, boom) {
		t.Fatalf("first attempt: got %v", err)
	}
	p, _ := m.GetProgress("d")
	if p.CurrentStep != 1 || len(p.History) != 1 {
		t.Fatalf("failed generation must not advance: %+v", p)
	}

	res, err := m.Act(req)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !res.Completed || string(res.Seal) != "seal" {
		t.Fatalf("res = %+v", res)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("generations = %d", n)
	}
}

func TestSlowSealDoesNotBlockOtherOperations(t *testing.T) {
	release := make(chan struct{})
	gen := func(body []byte, signer string, digest [32]byte) ([]byte, error) {
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
		return []byte("slow-seal"), nil
	}
	m := NewManager(gen)
	if err := m.CreateDocument("slow", signSteps(), []byte("A")); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateDocument("other", signSteps(), []byte("X")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Act(ActRequest{ReqID: "a1", DocID: "slow", Round: 1, Step: 0, Actor: "alice"}); err != nil {
		t.Fatal(err)
	}

	signDone := make(chan struct{})
	go func() {
		defer close(signDone)
		m.Act(ActRequest{ReqID: "g1", DocID: "slow", Round: 1, Step: 1, Actor: "bob"})
	}()
	time.Sleep(50 * time.Millisecond) // let the generation start

	check := func(name string, fn func() error) {
		t.Helper()
		start := time.Now()
		if err := fn(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d := time.Since(start); d > 200*time.Millisecond {
			t.Fatalf("%s took %v, want < 200ms", name, d)
		}
	}

	check("ReplaceBody", func() error { return m.ReplaceBody("slow", []byte("B")) })
	check("GetProgress", func() error {
		p, err := m.GetProgress("slow")
		if err != nil {
			return err
		}
		// No half-generated state: round 2, step 0, only the round-1 approval.
		if p.Round != 2 || p.CurrentStep != 0 || len(p.History) != 1 {
			t.Fatalf("inconsistent snapshot: %+v", p)
		}
		return nil
	})
	check("Act on other doc", func() error {
		_, err := m.Act(ActRequest{ReqID: "o1", DocID: "other", Round: 1, Step: 0, Actor: "alice"})
		return err
	})

	<-signDone
	p, _ := m.GetProgress("slow")
	if len(p.History) != 1 {
		t.Fatalf("discarded seal leaked into history: %+v", p.History)
	}
}

func TestHistoryDigestsMatchRoundBodies(t *testing.T) {
	m := NewManager(fastGen)
	if err := m.CreateDocument("d", signSteps(), []byte("v1")); err != nil {
		t.Fatal(err)
	}
	bodies := map[int][]byte{1: []byte("v1")}
	for round := 1; round <= 3; round++ {
		if round > 1 {
			body := []byte{byte('v'), byte('0' + round)}
			bodies[round] = body
			if err := m.ReplaceBody("d", body); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := m.Act(ActRequest{ReqID: string(rune('a'+round)) + "-a", DocID: "d", Round: round, Step: 0, Actor: "alice"}); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Act(ActRequest{ReqID: string(rune('a'+round)) + "-g", DocID: "d", Round: round, Step: 1, Actor: "bob"}); err != nil {
			t.Fatal(err)
		}
	}

	p, _ := m.GetProgress("d")
	if len(p.History) != 6 {
		t.Fatalf("history = %+v", p.History)
	}
	for _, r := range p.History {
		want := sha256.Sum256(bodies[r.Round])
		if r.Digest != want {
			t.Fatalf("round %d step %d: digest mismatch", r.Round, r.Step)
		}
		if r.Kind == StepSign && string(r.Seal) != "seal:"+string(bodies[r.Round]) {
			t.Fatalf("round %d: seal not bound to its body", r.Round)
		}
	}
}
