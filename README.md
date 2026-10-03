# task26100588

`docflow`：进程内文档签批推进库（Go）。

## 用法

```go
m := docflow.NewManager(func(body []byte, signer string, digest [32]byte) ([]byte, error) {
    return makeSeal(body, signer, digest) // 调用方提供的签章生成函数
})

m.CreateDocument("doc-1", []docflow.Step{
    {Kind: docflow.StepApprove, Assignee: "alice"},
    {Kind: docflow.StepSign,    Assignee: "bob"},
}, body)

res, err := m.Act(docflow.ActRequest{ReqID: "req-1", DocID: "doc-1", Round: 1, Step: 0, Actor: "alice"})
m.ReplaceBody("doc-1", newBody)        // 开启新轮次，全部步骤重新办理
p, err := m.GetProgress("doc-1")       // 一致快照：正文/轮次/当前步骤/历史
```

## 测试

```sh
go test -race ./...
```
