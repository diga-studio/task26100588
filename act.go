package docflow

import "errors"

// ErrInvalidRequest marks a malformed handling request.
var ErrInvalidRequest = errors.New("docflow: request id must not be empty")

// Act handles one step of a document for the given request. The request must
// name its target round and step explicitly. Repeating a successful request
// returns the original result without side effects; concurrent retries of a
// request whose seal is still being generated share that single generation.
func (m *Manager) Act(req ActRequest) (ActResult, error) {
	if req.ReqID == "" {
		return ActResult{}, ErrInvalidRequest
	}
	d, err := m.get(req.DocID)
	if err != nil {
		return ActResult{}, err
	}

	d.mu.Lock()

	// Idempotent replay of a previously successful request: return the
	// original result even across steps and rounds.
	if e, ok := d.done[req.ReqID]; ok {
		d.mu.Unlock()
		if e.req != req {
			return ActResult{}, ErrRequestConflict
		}
		return cloneResult(e.result), nil
	}

	// Concurrent retry of a request whose seal is being generated: wait for
	// the shared generation and report its outcome.
	if inf, ok := d.inflight[req.ReqID]; ok {
		if inf.req != req {
			d.mu.Unlock()
			return ActResult{}, ErrRequestConflict
		}
		doneCh := inf.done
		d.mu.Unlock()
		<-doneCh
		d.mu.Lock()
		defer d.mu.Unlock()
		if e, ok := d.done[req.ReqID]; ok {
			return cloneResult(e.result), nil
		}
		return ActResult{}, inf.err
	}

	// Validate the request against the current state.
	if req.Round != d.round {
		d.mu.Unlock()
		return ActResult{}, ErrStaleRound
	}
	if d.completed {
		d.mu.Unlock()
		return ActResult{}, ErrRoundCompleted
	}
	if req.Step != d.currentStep {
		d.mu.Unlock()
		return ActResult{}, ErrStaleStep
	}
	step := d.steps[req.Step]
	if step.Assignee != req.Actor {
		d.mu.Unlock()
		return ActResult{}, ErrNotAssignee
	}

	// Approval steps commit immediately under the lock.
	if step.Kind == StepApprove {
		res := d.commitLocked(req, step, nil)
		d.mu.Unlock()
		return res, nil
	}

	// Signing steps: register the in-flight generation, then run the slow
	// generator without holding the document lock so replacements, views and
	// other documents stay responsive.
	inf := &inflightSeal{req: req, done: make(chan struct{})}
	d.inflight[req.ReqID] = inf
	body := append([]byte(nil), d.body...)
	digest := d.digest
	round := d.round
	d.mu.Unlock()

	seal, genErr := m.gen(body, req.Actor, digest)

	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.inflight, req.ReqID)
	if genErr != nil {
		inf.err = genErr
		close(inf.done)
		return ActResult{}, genErr
	}
	// The round moved on (or the step was otherwise completed) while the
	// seal was being generated: the late result is discarded.
	if d.round != round || d.currentStep != req.Step {
		inf.err = ErrSealDiscarded
		close(inf.done)
		return ActResult{}, ErrSealDiscarded
	}
	res := d.commitLocked(req, step, seal)
	close(inf.done)
	return res, nil
}

// commitLocked records a successful handling and advances the workflow.
// Caller must hold d.mu.
func (d *document) commitLocked(req ActRequest, step Step, seal []byte) ActResult {
	d.history = append(d.history, Record{
		Round:  req.Round,
		Step:   req.Step,
		Kind:   step.Kind,
		Actor:  req.Actor,
		Digest: d.digest,
		Seal:   append([]byte(nil), seal...),
		ReqID:  req.ReqID,
	})
	d.currentStep++
	d.completed = d.currentStep == len(d.steps)

	res := ActResult{
		Round:     req.Round,
		Step:      req.Step,
		Kind:      step.Kind,
		Seal:      append([]byte(nil), seal...),
		Digest:    d.digest,
		Completed: d.completed,
	}
	d.done[req.ReqID] = doneEntry{req: req, result: res}
	return res
}

func cloneResult(res ActResult) ActResult {
	res.Seal = append([]byte(nil), res.Seal...)
	return res
}
