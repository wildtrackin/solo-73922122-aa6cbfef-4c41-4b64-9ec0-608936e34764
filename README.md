# BGP 路由起源 RPKI 核对

网络运维人员发布 BGP 路由前，核对前缀与起源 ASN 的 RPKI 授权（ROA）。
系统通过**固定的可信 RTR 源**，仅以 **RFC 8210 v1 Reset Query** 拉取全量
IPv4 授权（单次最多 1000 条），按 RFC 6483 给出 Valid / Invalid / NotFound
结论，并展示判定依据与数据版本。

## 快速开始

```bash
cp .env.example .env          # 可选：调整端口与 expire interval
docker compose up --build
```

启动后：

| 服务 | 地址 | 说明 |
| --- | --- | --- |
| Web 进程 A | http://localhost:8000 | 核对页（共享同一份数据库） |
| Web 进程 B | http://localhost:8001 | 第二个 Web 进程，验证跨进程共享 |
| RTR 源（协议） | `rtr-source:8210` / 宿主 `localhost:8210` | RFC 8210 v1 TCP |
| RTR 源（控制口） | http://localhost:8211 | 切换授权集 / 分片 / 断流 |

> 两个 Web 进程挂载同一个命名卷 `rpki-data`，SQLite 数据库位于
> `/data/rpki.db`，以 WAL 模式实现跨进程并发读写与持久共享。

## 网页演示流程

1. 打开 http://localhost:8000，此时**未同步**，页面提示“无法核对”。
2. 点击「手动同步全量授权」。同步在后台线程进行，页面查询与状态轮询不卡顿
   （网络等待不阻塞查询）。
3. 同步完成后，页面显示版本号、RTR 会话号、序号、到期时刻与授权条数。
4. 输入 IPv4 CIDR 与起源 ASN 进行核对，例如基线数据集：

| 输入 | 预期结论 | 依据 |
| --- | --- | --- |
| `198.51.100.0/24` + AS `64500` | Valid | 精确匹配授权，ASN 与 maxLength 均满足 |
| `198.51.100.64/26` + AS `64500` | Valid | 命中 maxLength=26 的更具体授权 |
| `198.51.100.0/24` + AS `64999` | Invalid | 有覆盖授权，但 ASN 不匹配 |
| `8.8.8.0/24` + AS `15169` | NotFound | 无任何 ROA 覆盖该前缀 |

5. 在 8000 与 8001 两个页面分别核对，结论与版本完全一致（同版完整数据）。

### 切换本地 RTR 源行为（控制口 :8211）

```bash
# 查看当前状态
curl -s localhost:8211/state | python3 -m json.tool

# 切换授权集（baseline / alternate），序号自动递增
curl -s -X POST localhost:8211/dataset -d '{"dataset":"alternate"}'

# 每个 PDU 拆成 3 字节小 TCP 段发送（验证分片/粘包处理）
curl -s -X POST localhost:8211/mode -d '{"mode":"fragment"}'

# End of Data 到达前断流 -> 同步失败，页面保留旧版本可继续核对
curl -s -X POST localhost:8211/mode -d '{"mode":"drop-eod"}'

# 只回 Cache Reset / 发送一半断开 / 回 Error Report
curl -s -X POST localhost:8211/mode -d '{"mode":"drop-reset"}'
curl -s -X POST localhost:8211/mode -d '{"mode":"drop-mid"}'
curl -s -X POST localhost:8211/mode -d '{"mode":"error"}'

# 恢复正常
curl -s -X POST localhost:8211/mode -d '{"mode":"clean"}'
```

将 `.env` 中 `EXPIRE_INTERVAL` 调小（如 120）后重新 `docker compose up`，
可在两分钟后观察到“授权已过期，无法核对”。

## 判定规则（RFC 6483）

对一条待发布的 IPv4 前缀 P 与起源 ASN A：

- **覆盖授权**：ROA 前缀是 P 的超网，且 ROA 的 `maxLength >= P 的前缀长度`；
- **Valid**：任一覆盖授权同时满足 `ROA.ASN == A` 且 maxLength 允许该长度；
- **Invalid**：存在覆盖授权，但没有任何一条同时匹配 ASN 与 maxLength；
- **NotFound**：不存在任何覆盖授权。

页面会列出全部覆盖授权（前缀、ASN、maxLength、ASN 是否匹配）作为依据，
并标注结论所依据的版本号、RTR 会话号、序号与到期时刻。

## 一致性与故障语义

- **按 PDU 长度处理 TCP 分片/粘包**：先缓冲字节流，再按公共头部的
  32 位 `length` 字段切帧；半个 PDU、一次多个 PDU 都能正确重组。
- **全量合法性门控**：只有从 `Cache Response` 到**同会话** `End of Data`
  的所有 PDU 全部合法（版本、长度、会话号、序号、计时字段、前缀/ASN
  范围、无撤回 PDU、无 IPv6、≤1000 条）才落库；任一异常整轮作废。
- **原子版本写入**：版本行与授权行在单个 SQLite 事务中提交，读者永远
  只能看到完整的同版数据，不会读到半成品。
- **断流/错误保留旧版**：同步失败不触碰当前版本，旧版在到期前继续可用。
- **代际冲突丢弃**：同步开始时记录数据库代际，提交时若当前版本已被另一个
  Web 进程替换，则丢弃本次结果。
- **到期时刻**：从 End of Data PDU 完整到达时刻起，按其 `expire` interval
  计算；过期后查询接口返回“无法核对”。
- **网络不阻塞查询**：同步在守护线程执行，API 线程池不等待 RTR 网络。

## 目录结构

```
app/
  main.py        FastAPI 路由与状态接口
  rtr.py         RFC 8210 客户端：Reset Query、帧读取、全量校验
  storage.py     SQLite(WAL) 版本化存储、代际检查、原子提交
  validator.py   RFC 6483 Valid/Invalid/NotFound 判定与输入校验
  sync.py        后台同步编排与状态机
  static/        核对页前端（原生 JS，严格 CSP）
rtr_source/
  server.py      本地 RTR 源（RTR TCP + HTTP 控制口，6 种故障模式）
  Dockerfile
tests/           48 个 unittest 用例（协议/存储/校验/同步/API）
```

## 测试

```bash
python3 -m unittest discover -s tests -v
```

协议、存储、校验与同步测试仅依赖标准库；API 端到端测试需要
`requirements.txt` 中的 FastAPI 环境（容器内自动满足，缺依赖时自动跳过）。
