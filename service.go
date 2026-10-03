package docsign

import (
	"errors"
	"sync"
	"time"
)

// Service 是文档签批推进库的主入口，全部状态保存在进程内。
type Service struct {
	mu       sync.Mutex
	docs     map[string]*document
	requests map[string]*requestEntry
}

// commandKey 标识一条业务命令，用于检测请求标识被复用到不同命令。
type commandKey struct {
	docID     string
	round     int
	stepIndex int
	operator  string
}

// requestEntry 记录一个请求标识的办理状态。
// 签章生成期间 done 未关闭，并发重试等待 done 共享同一次结果。
type requestEntry struct {
	cmd    commandKey
	done   chan struct{}
	ok     bool
	result HandleResult
	err    error
}

// document 是单份文档的内部状态。
type document struct {
	steps   []Step
	round   int
	current int
	body    []byte
	digest  [32]byte
	history []Record
	pending *requestEntry // 正在生成签章的在途请求，无则为 nil
}

// New 创建一个空的 Service。
func New() *Service {
	return &Service{docs: make(map[string]*document), requests: make(map[string]*requestEntry)}
}

// CreateDocument 创建文档并写入首轮正文；若文档已存在则返回错误。
func (s *Service) CreateDocument(docID string, steps []Step, body []byte) error {
	if err := validateSteps(steps); err != nil {
		return err
	}
	if len(body) > MaxBodySize {
		return ErrBodyTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.docs[docID]; ok {
		return ErrAlreadyExists
	}
	s.docs[docID] = &document{
		steps:   append([]Step(nil), steps...),
		round:   1,
		current: 0,
		body:    append([]byte(nil), body...),
		digest:  digestOf(body),
	}
	return nil
}

// ReplaceBody 替换正文并开启新轮次，全部步骤重新办理。
func (s *Service) ReplaceBody(docID string, body []byte) (round int, err error) {
	if len(body) > MaxBodySize {
		return 0, ErrBodyTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, ok := s.docs[docID]
	if !ok {
		return 0, ErrNotFound
	}
	doc.round++
	doc.current = 0
	doc.body = append([]byte(nil), body...)
	doc.digest = digestOf(body)
	// 正在生成的旧轮次签章在提交时会发现轮次已过期而作废，
	// 这里不等待生成结束。
	return doc.round, nil
}

// Handle 办理指定轮次的指定步骤。
// 同一 RequestID 重复调用返回原成功结果；签章生成期间并发重试共享同一次生成。
func (s *Service) Handle(req HandleRequest, gen SealGenerator) (HandleResult, error) {
	cmd := commandKey{docID: req.DocID, round: req.Round, stepIndex: req.StepIndex, operator: req.Operator}

	s.mu.Lock()
	if ent, ok := s.requests[req.RequestID]; ok {
		if ent.cmd != cmd {
			s.mu.Unlock()
			return HandleResult{}, ErrRequestConflict
		}
		if ent.ok || ent.err != nil {
			// 已完结（成功或已作废/失败）：直接返回原结果。
			res, err, ok := ent.result, ent.err, ent.ok
			s.mu.Unlock()
			if !ok {
				return HandleResult{}, err
			}
			return res, nil
		}
		// 正在生成签章：等待并共享这次生成的结果。
		done := ent.done
		s.mu.Unlock()
		<-done
		s.mu.Lock()
		res, err, ok := ent.result, ent.err, ent.ok
		s.mu.Unlock()
		if !ok {
			return HandleResult{}, err
		}
		return res, nil
	}

	doc, ok := s.docs[req.DocID]
	if !ok {
		s.mu.Unlock()
		return HandleResult{}, ErrNotFound
	}
	if err := checkTargetLocked(doc, req); err != nil {
		s.mu.Unlock()
		return HandleResult{}, err
	}
	step := doc.steps[req.StepIndex]

	if step.Kind == StepApprove {
		// 审批无外部生成，锁内原子完成。
		rec := Record{
			Round:      req.Round,
			StepIndex:  req.StepIndex,
			Kind:       step.Kind,
			Handler:    req.Operator,
			BodyDigest: doc.digest,
			FinishedAt: time.Now(),
		}
		res := commitLocked(doc, rec)
		s.requests[req.RequestID] = &requestEntry{cmd: cmd, ok: true, result: res}
		s.mu.Unlock()
		return res, nil
	}

	// 签署步骤：登记在途请求后释放锁，在锁外执行可能缓慢的生成。
	if gen == nil {
		s.mu.Unlock()
		return HandleResult{}, errors.New("docsign: seal generator is required for sign step")
	}
	ent := &requestEntry{cmd: cmd, done: make(chan struct{})}
	s.requests[req.RequestID] = ent
	doc.pending = ent
	body := append([]byte(nil), doc.body...)
	digest := doc.digest
	s.mu.Unlock()

	attachment, genErr := gen(body, req.Operator, digest)

	s.mu.Lock()
	defer s.mu.Unlock()
	if doc.pending == ent {
		doc.pending = nil
	}
	if genErr != nil {
		// 生成失败不推进，删除登记以允许原请求标识重试。
		delete(s.requests, req.RequestID)
		ent.err = genErr
		close(ent.done)
		return HandleResult{}, genErr
	}
	if doc.round != req.Round || doc.current != req.StepIndex {
		// 生成期间已换版或步骤已被推进：结果作废，不推进也不补记。
		delete(s.requests, req.RequestID)
		ent.err = ErrStaleRound
		close(ent.done)
		return HandleResult{}, ErrStaleRound
	}
	rec := Record{
		Round:      req.Round,
		StepIndex:  req.StepIndex,
		Kind:       step.Kind,
		Handler:    req.Operator,
		BodyDigest: digest,
		Attachment: append([]byte(nil), attachment...),
		FinishedAt: time.Now(),
	}
	res := commitLocked(doc, rec)
	ent.ok = true
	ent.result = res
	close(ent.done)
	return res, nil
}

// checkTargetLocked 校验办理请求是否指向当前轮次的当前步骤，调用时需持锁。
func checkTargetLocked(doc *document, req HandleRequest) error {
	if req.Round != doc.round {
		return ErrStaleRound
	}
	if doc.current >= len(doc.steps) {
		return ErrRoundCompleted
	}
	if req.StepIndex != doc.current {
		return ErrNotCurrentStep
	}
	if doc.pending != nil && doc.pending.cmd.round == req.Round && doc.pending.cmd.stepIndex == req.StepIndex {
		return ErrStepBusy
	}
	if doc.steps[req.StepIndex].Handler != req.Operator {
		return ErrNotHandler
	}
	return nil
}

// commitLocked 追加成功记录并推进到下一步，调用时需持锁。
func commitLocked(doc *document, rec Record) HandleResult {
	doc.history = append(doc.history, rec)
	doc.current++
	return HandleResult{
		Round:      rec.Round,
		StepIndex:  rec.StepIndex,
		Kind:       rec.Kind,
		BodyDigest: rec.BodyDigest,
		Attachment: append([]byte(nil), rec.Attachment...),
		AdvancedTo: doc.current,
		Completed:  doc.current >= len(doc.steps),
	}
}

// Progress 返回文档某一时刻的完整一致快照。
func (s *Service) Progress(docID string) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, ok := s.docs[docID]
	if !ok {
		return Snapshot{}, ErrNotFound
	}
	snap := Snapshot{
		DocID:       docID,
		Round:       doc.round,
		CurrentStep: doc.current,
		Completed:   doc.current >= len(doc.steps),
		Steps:       append([]Step(nil), doc.steps...),
		Body:        append([]byte(nil), doc.body...),
		BodyDigest:  doc.digest,
		History:     make([]Record, len(doc.history)),
	}
	for i, rec := range doc.history {
		rec.Attachment = append([]byte(nil), rec.Attachment...)
		snap.History[i] = rec
	}
	return snap, nil
}

// validateSteps 校验步骤定义：2..10 步，每步办理人非空。
func validateSteps(steps []Step) error {
	if len(steps) < MinSteps || len(steps) > MaxSteps {
		return ErrInvalidSteps
	}
	for _, st := range steps {
		if st.Handler == "" || (st.Kind != StepApprove && st.Kind != StepSign) {
			return ErrInvalidSteps
		}
	}
	return nil
}
