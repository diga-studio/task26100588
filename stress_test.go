package docsign

import (
	"fmt"
	"sync"
	"testing"
)

// TestStressManyDocsConcurrent：100 份文档、32 个并发工作者混合操作。
func TestStressManyDocsConcurrent(t *testing.T) {
	s := New()
	const docs = 100
	for i := 0; i < docs; i++ {
		mustCreate(t, s, fmt.Sprintf("doc-%d", i), twoSteps(), "A")
	}
	const workers = 32
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < docs; i += workers {
				docID := fmt.Sprintf("doc-%d", i)
				if _, err := s.Handle(HandleRequest{RequestID: "a-" + docID, DocID: docID, Round: 1, StepIndex: 0, Operator: "alice"}, nil); err != nil {
					t.Errorf("%s approve: %v", docID, err)
					return
				}
				if _, err := s.Handle(HandleRequest{RequestID: "s-" + docID, DocID: docID, Round: 1, StepIndex: 1, Operator: "bob"}, sealOK); err != nil {
					t.Errorf("%s sign: %v", docID, err)
					return
				}
				if _, err := s.ReplaceBody(docID, []byte("B")); err != nil {
					t.Errorf("%s replace: %v", docID, err)
					return
				}
				snap, err := s.Progress(docID)
				if err != nil {
					t.Errorf("%s progress: %v", docID, err)
					return
				}
				if snap.Round != 2 || snap.CurrentStep != 0 || len(snap.History) != 2 {
					t.Errorf("%s inconsistent snapshot: %+v", docID, snap)
					return
				}
			}
		}(w)
	}
	wg.Wait()
}
