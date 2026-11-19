# pairwise-audit-log

## 题面

重试与补写叠加时，审计日志本身开始不可信：并发追加不是原子写，长行被拆成多次 write，行与行交错、序号重复；值里的换行不转义，一条日志能伪造出两行；时间戳不做单调校验，时钟回拨后可以插入旧事件；脱敏只处理顶层精确键名，嵌套对象和大小写变体全漏；没有哈希链与重放窗口，改一行也发现不了，重放请求还能再记一遍。auditlog/writer.py 是核心，tests/test_writer.py 15个红。要修的是：单次 O_APPEND 整行写入并按序分配 seq；值内换行与回车转义；时间戳单调不减校验；脱敏支持嵌套、大小写与通配；HMAC 哈希链加窗口内重放去重。

## 运行方式

在仓库根目录执行：

```powershell
python -m pytest tests -q
```

初始状态应恰好得到 15 个失败，且没有 collection error、import error 或 syntax error。输出最后一行的形式为：

```text
15 failed in 0.12s
```

初始失败只来自 `auditlog/writer.py` 中的契约桩，不是测试本身出错。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 基线

`tests/` 是验收基线，不可修改；实现只应落在 `auditlog/writer.py`。需要落盘的测试均使用 `tmp_path`，时间通过 `now` 显式传入，并发只使用标准库 `threading.Barrier` 与计数，不联网、不使用随机数。
