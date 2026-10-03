// Package docsign 提供进程内的文档签批推进能力。
package docsign

import (
	"crypto/sha256"
	"errors"
	"time"
)

// MaxBodySize 是正文允许的最大字节数（1MiB）。
const MaxBodySize = 1 << 20

// 步骤数量限制。
const (
	MinSteps = 2
	MaxSteps = 10
)

// StepKind 表示步骤类型：审批或签署。
type StepKind int

const (
	// StepApprove 审批步骤。
	StepApprove StepKind = iota
	// StepSign 签署步骤，需要生成签章附件。
	StepSign
)

// Step 是文档创建时固定的一个串行步骤。
type Step struct {
	Kind    StepKind
	Handler string // 该步骤唯一办理人
}

// Record 是某一轮次中一个已成功步骤的办理记录。
type Record struct {
	Round      int       // 所属轮次（从 1 开始）
	StepIndex  int       // 步骤下标（从 0 开始）
	Kind       StepKind  // 步骤类型
	Handler    string    // 实际办理人
	BodyDigest [32]byte  // 该轮次正文的 SHA-256 摘要
	Attachment []byte    // 签章附件（仅签署步骤非空）
	FinishedAt time.Time // 成功时间
}

// Snapshot 是某一时刻文档的完整一致状态。
type Snapshot struct {
	DocID       string
	Round       int      // 当前轮次
	CurrentStep int      // 当前待办步骤下标；本轮全部完成时为 len(Steps)
	Completed   bool     // 当前轮次是否已全部完成
	Steps       []Step   // 固定步骤定义
	Body        []byte   // 当前轮次正文副本
	BodyDigest  [32]byte // 当前正文 SHA-256
	History     []Record // 全部轮次的成功记录，按时间顺序
}

// HandleRequest 是一次办理请求。
type HandleRequest struct {
	RequestID string // 请求标识，同一标识只用于同一业务命令
	DocID     string
	Round     int // 目标轮次
	StepIndex int // 目标步骤下标
	Operator  string
}

// HandleResult 是办理成功后的结果。
type HandleResult struct {
	Round      int
	StepIndex  int
	Kind       StepKind
	BodyDigest [32]byte
	Attachment []byte // 签章附件（仅签署步骤非空）
	AdvancedTo int    // 办理后推进到的步骤下标
	Completed  bool   // 办理后本轮是否全部完成
}

// SealGenerator 由调用方提供，进程内生成签章附件。
// 输入为目标轮次正文、签署人及正文 SHA-256 摘要。
type SealGenerator func(body []byte, signer string, digest [32]byte) ([]byte, error)

// 库对外暴露的错误。
var (
	ErrAlreadyExists   = errors.New("docsign: document already exists")
	ErrNotFound        = errors.New("docsign: document not found")
	ErrInvalidSteps    = errors.New("docsign: steps must be 2..10 each with a non-empty handler")
	ErrBodyTooLarge    = errors.New("docsign: body exceeds 1MiB")
	ErrStaleRound      = errors.New("docsign: target round is not the current round")
	ErrNotCurrentStep  = errors.New("docsign: target step is not the current step")
	ErrRoundCompleted  = errors.New("docsign: target round already completed")
	ErrNotHandler      = errors.New("docsign: operator is not the handler of this step")
	ErrStepBusy        = errors.New("docsign: another request is handling this step")
	ErrRequestConflict = errors.New("docsign: request id already used for a different command")
)

// digestOf 计算正文的 SHA-256 摘要。
func digestOf(body []byte) [32]byte {
	return sha256.Sum256(body)
}
