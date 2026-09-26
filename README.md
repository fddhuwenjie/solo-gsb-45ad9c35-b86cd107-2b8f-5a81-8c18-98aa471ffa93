# TLS 证书无中断轮换规划 API

给定客户端信任锚、各 TLS 端点当前/目标证书链、必须保持的通信关系，以及一组
**增信 (add_trust)**、**换证 (replace_cert)**、**撤信 (remove_trust)** 动作
（每个动作带 `allowed_stages`），本服务计算**阶段数最少**的轮换计划，使得每个阶段
完成后所有通信关系仍存在有效的信任路径（从端点叶子到客户端某个信任锚的完整链）。
也支持逐阶段回放任意计划，定位首次失效的关系、阻塞动作与断开的证书链。
部署中断后可用 `/plans/reconcile` 结合部分现场观测枚举所有可能进度并给出
安全的下一步动作。
另提供**部署身份预检**：在规划前校验目标叶证书的 SAN 是否覆盖端点声明的
DNS/IP 身份，并沿链累计中间 CA 的名称约束（excluded 优先、permitted 取交集）。
还提供**离线 OCSP 装订预检**：不联系响应方，核对装订 OCSP 响应的 CertID、
授权签名者（签发者本人或直接签发且含 id-kp-OCSPSigning 的委托响应证书）、
签名、certStatus 与新鲜度窗口，决定该响应是否可随目标叶一起部署。

## 一键启动

```bash
docker compose up --build
```

- 端口：`http://localhost:8080`
- 交互式 API 文档：`http://localhost:8080/docs`
- 健康检查：`GET /health`

停止：`docker compose down`。

## 接口

### `POST /scenarios/normalize` — 乱序 PEM 包归一化

把一份**乱序、可能含重复 DER 副本**的 PEM 证书包，连同各端点当前/目标叶证书的
SHA-256 指纹、以及允许作为链终点的自签名根指纹，归一化为规划器可直接使用的数据。

```bash
curl -s http://localhost:8080/scenarios/normalize \
  -H 'Content-Type: application/json' \
  --data @examples/normalize_request.json
```

请求字段：

| 字段 | 说明 |
| --- | --- |
| `pem_certificates` | PEM 字符串列表；顺序任意，每个元素可含多个拼接的 PEM CERTIFICATE 块，按 DER 指纹去重 |
| `endpoints[].current_leaf_fingerprint` / `target_leaf_fingerprint` | 端点当前/目标叶证书的 SHA-256（十六进制，大小写不敏感，输出统一为小写） |
| `trust_roots` | 允许作为链终点的自签名根证书指纹列表 |

签发关系**只通过签名验证建立**——用候选签发者公钥验证子证书的签名
（支持 RSA PKCS#1 v1.5、RSA-PSS、ECDSA、DSA、Ed25519/Ed448），绝不仅比较
subject/issuer：同名不同密钥的「冒牌 CA」、交叉签名证书都会被正确区分。

随后对每张叶证书在「已验证签发边」构成的图上判定可信路径（leaf-first、
到达某个声明信任根的简单路径）的数目是**零条、恰好一条还是多条**——只有
恰好一条时才输出结果。该判定是**精确**的：通过一次路径搜索加上多项式复杂度的
「是否存在第二条不同路径」检查完成，**不枚举全部简单路径**（最坏情况下是阶乘级），
因此含环、共享中间证书、大量交叉签名分支的包都不会让判定超时或误判。

成功返回 `200`，`cert_id` 一律为小写 SHA-256，证书含现有模型所需的
`subject`、`issuer`、`not_valid_before`、`not_valid_after`，端点含还原好的
`current_chain`、`target_chain`（叶在前、根在后），可直接拼入 `/plans` 请求体：

```json
{
  "certificates": [
    {"cert_id": "0164c42f...", "subject": "CN=api.example.com",
     "issuer": "CN=Old Root CA",
     "not_valid_before": "2024-01-01T00:00:00Z",
     "not_valid_after": "2035-01-01T00:00:00Z"}
  ],
  "endpoints": [
    {"endpoint_id": "api.example.com",
     "current_chain": ["0164c42f...", "a6f01a66..."],
     "target_chain": ["4e822998...", "951ac9d4...", "6f5b46a2..."]}
  ]
}
```

以下情况返回 `422`，错误体在 `detail` 中给出机器可读 `error`、`message` 与逐条诊断
（`pem_issues` / `fingerprint_issues` / `chain_issues`）。`chain_issues` 会列出
无法确定链的**叶证书指纹**、签名真正通过的**候选签发者指纹** `candidate_issuers`，
以及**候选路径指纹** `candidate_paths`：

- `no_trust_path`：不存在从叶证书经签名验证到达信任根的路径（缺上级、签名不匹配、
  PEM 被篡改等）。
- `ambiguous_chain`：交叉签名导致存在多条都能到达信任根的有效路径，归一化拒绝替你
  猜测；典型场景与响应见
  [`examples/normalize_ambiguous_request.json`](examples/normalize_ambiguous_request.json)。
- `invalid_pem`：某个列表元素不是可解析的 PEM（附元素下标）。
- `invalid_fingerprint` / `unknown_fingerprint`：指纹不是 64 位十六进制 SHA-256，
  或包内没有任何证书与该指纹匹配。
- `trust_root_not_self_signed`：声明的信任根不是自签名证书
  （subject != issuer 或自签名验证失败）。

> **`candidate_paths` 只是有界诊断样本**：为避免阶乘级枚举，诊断遍历最多记录
> **64** 条候选路径，交叉签名极多的包中样本可能被截断。截断只影响展示，
> 不影响结论——`no_trust_path` / `ambiguous_chain` / 成功（200）的判定始终
> 基于完整的签发图精确计算，与样本大小无关。

注意：归一化只确认**密码学签发关系**，不检查有效期（没有规划时刻输入）；有效期校验
仍由 `/plans` 的 `plan_time` 负责。示例 PEM 可用
`examples/gen_normalize_example.py` 与 `examples/gen_normalize_ambiguous_example.py`
重新生成。

### `POST /deployments/precheck` — 目标证书部署身份预检

在把目标证书交给规划器之前，先验证它**真的为各端点声明的 DNS/IP 身份签名**，
并且整条链上的中间 CA 名称约束允许这些身份。输入与归一化接口相同的 PEM 包
（同样的解析、去重、签名验证链重建规则），外加每个端点的目标叶指纹和身份声明：

```bash
curl -s http://localhost:8080/deployments/precheck \
  -H 'Content-Type: application/json' \
  --data @examples/precheck_request.json
```

请求字段：

| 字段 | 说明 |
| --- | --- |
| `pem_certificates` / `trust_roots` | 与 `/scenarios/normalize` 相同 |
| `endpoints[].target_leaf_fingerprint` | 目标叶证书的 SHA-256 指纹（大小写不敏感） |
| `endpoints[].identities[]` | 端点声明的身份：`{"type": "dns", "value": "api.example.com"}` 或 `{"type": "ip", "value": "10.0.0.7"}` |

身份检查规则：

- **只认 SAN**：subject CN 不作为身份来源；声明的身份必须由叶证书同类型
  SAN 条目覆盖。
- **DNS 归一化**：统一小写、剥掉末尾单点、非 ASCII 标签转 IDNA A-label
  （`BÜCHER.example` 与 `xn--bcher-kva.example` 视为同一身份）。
- **通配符**：SAN 中的 `*` 只能占最左侧完整标签，且只匹配**一个**标签
  （`*.example.com` 覆盖 `api.example.com`，不覆盖 `example.com` 或
  `a.b.example.com`）；声明的身份里不允许出现通配符。
- **IP 精确匹配**：声明必须是字面 IPv4/IPv6 地址（不接受网段、zone id），
  与 iPAddress SAN 逐字节相等才算覆盖，v4/v6 互不混淆。
- **名称约束沿链累计**：只累计中间 CA（信任锚自身的约束不重复执行）；
  `excluded` 优先于 `permitted`，多个 CA 的 `permitted` 取**交集**
  （叶 SAN 必须落在每个施加了该类型约束的 CA 的允许集内）。DNS 约束按
  标签边界匹配（`example.com` 约束覆盖 `api.example.com`，不覆盖
  `evil-example.com`；`.example.com` 只覆盖子域）；IP 约束按地址+掩码
  网段判断。对每类声明的身份，**叶证书上全部同类 SAN 都会被校验**，
  不只是被声明引用的那些——任何一个同类 SAN 违反约束，端点即不合格
  （未声明的类型不参与判定）。**通配符 SAN 按其覆盖集合整体求值**
  （`*.example.com` 视为「`example.com` 下任意单个标签」的集合），不做
  字面名校验、也不抽样枚举：覆盖集合与任一 `excluded` 子树**相交**即拒
  （如 `excluded: blocked.example.com` 会命中 `*.example.com`，而
  `.blocked.example.com` 只排除更深层名字、与之不相交）；同时该集合必须
  被每级 CA 的 `permitted` 并集**完整容纳**（`permitted: api.example.com`
  这类窄许可容不下整个通配集合）。
- **不支持的约束类型**（rfc822Name、URI、directoryName、otherName 等，或
  畸形的 iPAddress 约束）一律按失败关闭处理，返回
  `unsupported_constraint_type`，绝不静默放行。

成功返回 `200`，`results` 按 `endpoint_id` 稳定排序；每个结果给出
`eligible`、机器可读 `reason`、重建好的叶在前 `chain`（即规划接口的
`target_chain`）、归一化后的 `dns_sans` / `ip_sans`、逐身份覆盖结果
`identities` 和稳定排序的 `violations`：

```json
{
  "results": [
    {
      "endpoint_id": "api.example.com",
      "target_leaf_fingerprint": "e72201b1...",
      "eligible": true,
      "reason": "ok",
      "chain": ["e72201b1...", "acd82986...", "4c9094c3..."],
      "dns_sans": ["*.svc.example.com", "api.example.com"],
      "ip_sans": ["10.0.0.7"],
      "identities": [
        {"type": "dns", "value": "api.example.com", "covered": true},
        {"type": "dns", "value": "grpc.svc.example.com", "covered": true},
        {"type": "ip", "value": "10.0.0.7", "covered": true}
      ],
      "violations": []
    }
  ]
}
```

`reason` 取值（同时是 violations 的稳定排序优先级）：

- `unsupported_constraint_type`：链上存在无法对 DNS/IP 身份求值的约束类型。
- `excluded_by_name_constraint`：某个 SAN（通配符按其覆盖集合）与
  excluded 子树相交。
- `not_within_permitted_subtree`：某个 SAN（通配符按其覆盖集合）未落入
  每级 CA 的 permitted 交集。
- `identity_not_covered`：声明的身份没有任何存活的同类型 SAN 覆盖。

每条 violation 携带 `identity_type` / `identity_value` / `san` /
`constraint` / `ca_fingerprint` 字段定位原因。**只有 `eligible: true` 的
结果才应交给 `/plans`**；其 `chain` 可直接作为端点的 `target_chain` 拼入
规划请求（示例见 [`examples/precheck_request.json`](examples/precheck_request.json)，
可用 `examples/gen_precheck_example.py` 重新生成）。

请求级错误返回 `422`，结构与归一化接口一致（`error`、`message`、
`pem_issues` / `fingerprint_issues` / `chain_issues`），并额外提供
`identity_issues`（非法 DNS/IP 身份、重复身份，错误码 `invalid_identity`）；
链无法唯一解析时同样返回 `no_trust_path` / `ambiguous_chain`。

### `POST /deployments/ocsp-precheck` — 离线预检 OCSP 装订响应

在部署前**完全离线**校验一张目标叶证书的 OCSP 装订响应（RFC 6960），无需联系
任何响应方。输入与归一化接口同款的 PEM 包（复用其解析、去重与签名验证原语），
外加叶指纹、Base64 DER OCSP 响应、校验时刻与最多 300 秒的时钟偏差：

```bash
curl -s http://localhost:8080/deployments/ocsp-precheck \
  -H 'Content-Type: application/json' \
  --data @examples/ocsp_precheck_request.json
```

请求字段：

| 字段 | 说明 |
| --- | --- |
| `pem_certificates` | PEM 字符串列表，规则同 `/scenarios/normalize`；需包含目标叶及其签发者 |
| `leaf_fingerprint` | 响应所应描述的叶证书 SHA-256 指纹（十六进制，大小写不敏感） |
| `ocsp_response` | 装订在握手上的 Base64 DER OCSP 响应（容忍换行空白） |
| `check_time` | 校验时刻（ISO-8601，建议带时区；裸时间按 UTC，输出统一归一化为 UTC） |
| `allowed_skew_seconds` | 响应方时钟偏差容忍，`0..300`，缺省 `300`，对新鲜度窗口两侧对称放宽 |

校验严格按 RFC 6960 逐层进行：

1. **CertID 必须点名该叶**：序列号必须与叶证书一致；`issuerNameHash` 与
   `issuerKeyHash`（按 CertID 自带的哈希算法重新计算，名字哈希覆盖签发者 DN、
   密钥哈希覆盖 subjectPublicKey BIT STRING 内容）必须同时命中 PEM 包中一张
   **密码学上真正签发了该叶**的证书——只比对 DN 或只比对密钥都不足以通过。
2. **按 ResponderID 选定签名者**：只接受两类——①叶的签发者本身（byName 匹配
   subject DN，或 byKey 匹配其公钥 SHA-1，CA 自签 OCSP 无需 EKU）；②响应内嵌的
   委托响应证书，必须**由该签发者直接签发**、在 `check_time` 处于有效期内、
   且含 `id-kp-OCSPSigning`（1.3.6.1.5.5.7.3.9）扩展。
3. **验签**：用选定签名者公钥验证 BasicOCSPResponse 对 responseData 的签名
   （RSA PKCS#1 v1.5、RSA-PSS、ECDSA、DSA、Ed25519/Ed448；PSS 参数直接按
   RFC 4055 从原始 AlgorithmIdentifier 解析，MGF1 摘要必须一致，无法解析即失败关闭）。
4. **状态与新鲜度**：`responseStatus` 必须为 `successful` 且 `certStatus` 必须为
   `good`；`producedAt` 不得晚于 `check_time + skew`；`nextUpdate` 必填；
   `check_time`（两侧各放宽 skew）必须落在 `thisUpdate .. nextUpdate` 窗口内。

全部满足才返回 `eligible: true`；否则 `eligible: false` 并给出**稳定原因**。
成功/失败都回显归一化后的 `check_time`、`response_status`、`cert_status`、
`produced_at` / `this_update` / `next_update`、`responder_type`
（`by_name` / `by_key`）以及实际验签所用证书的 `signer_fingerprint`：

```json
{
  "eligible": true,
  "reason": "ok",
  "check_time": "2026-09-01T12:00:00Z",
  "response_status": "successful",
  "cert_status": "good",
  "produced_at": "2026-09-01T11:55:00Z",
  "this_update": "2026-09-01T11:00:00Z",
  "next_update": "2026-09-08T12:00:00Z",
  "revocation_time": null,
  "revocation_reason": null,
  "responder_type": "by_name",
  "signer_fingerprint": "ef90aa96...",
  "message": "good OCSP response signed by an authorized responder ..."
}
```

稳定 `reason` 取值（按校验顺序，短路返回）：

- `invalid_ocsp_response`：Base64 解出的 DER 不是可解析的 OCSPResponse
  （注意：Base64 本身非法属于请求错误 `422`）。
- `unexpected_single_response_count`：successful 响应中的 SingleResponse
  条数不是恰好一条（装订只针对一张证书，零条或多条都无法给出单一结论）。
- `response_not_successful`：`responseStatus` 非 successful
  （`malformed_request` / `internal_error` / `try_later` / `sig_required` /
  `unauthorized`），此时没有 certStatus 可看。
- `serial_mismatch`：CertID 序列号与叶不符。
- `certid_issuer_mismatch`：包内没有证书既密码学签发了叶、又同时匹配
  CertID 的两个哈希。
- `responder_untrusted`：ResponderID 既不匹配签发者，也不匹配一张直接签发、
  当前有效且含 `id-kp-OCSPSigning` 的内嵌响应证书（缺失、过期、无 EKU、
  非该签发者所签均归此因）。
- `invalid_signature`：响应签名在选定签名者公钥下验证失败。
- `certificate_revoked`：certStatus 为 revoked；额外回显 `revocation_time`
  与 `revocation_reason`（RFC 5280 CRLReason 枚举名，如 `key_compromise`、
  `ca_compromise`、`cessation_of_operation`；响应未给原因时按 RFC 5280
  默认 `unspecified`）。
- `certificate_unknown`：certStatus 为 unknown。
- `produced_at_too_late`：`producedAt` 晚于 `check_time + skew`。
- `missing_next_update`：singleResponse 不含必填的 `nextUpdate`。
- `before_this_update` / `after_next_update`：`check_time`（加 skew 后）
  早于 `thisUpdate` / 晚于 `nextUpdate`。

请求信封本身错误返回 `422`，沿用归一化的错误结构：`invalid_pem`（PEM 元素
不可解析）、`invalid_fingerprint` / `unknown_fingerprint`、
`invalid_ocsp_response`（`ocsp_response` 不是合法 Base64）、以及
`allowed_skew_seconds` 超出 `0..300` 的模式校验。示例请求见
[`examples/ocsp_precheck_request.json`](examples/ocsp_precheck_request.json)，
可用 `examples/gen_ocsp_precheck_example.py` 重新生成。

### `POST /plans` — 求最优计划

请求体见 [`examples/plan_request.json`](examples/plan_request.json)：

```bash
curl -s http://localhost:8080/plans \
  -H 'Content-Type: application/json' \
  --data @examples/plan_request.json
```

成功返回 `200`：

```json
{
  "status": "ok",
  "stage_count": 2,
  "stages": [
    {"stage": 1, "action_ids": ["a1-add-new-root"]},
    {"stage": 2, "action_ids": ["a2-serve-new-leaf", "a3-remove-old-root"]}
  ]
}
```

说明：

- 计划阶段数最少（经典根轮换即「先增信 → 换证与撤信并行」两步）。
- 存在多个最优解时，按动作的 `action_id` 排序后取各动作所在阶段号向量的
  字典序最小解，保证结果稳定、与输入顺序无关；每个阶段内的动作也按
  `action_id` 升序输出。
- 阶段内的动作视为并行生效；对同一信任锚同时增信与撤信是未定义的，会被禁止
  排到同一阶段。
- 阶段号是**绝对阶段号**：动作最早可能只能在较晚的阶段执行（例如唯一允许的
  阶段是 2）。此前的空阶段作为 **no-op（空操作）阶段**显式保留——信任状态
  原样跨过空档，每个阶段结束后仍校验全部信任关系。响应中以真实阶段号输出，
  空阶段形如 `{"stage": 1, "action_ids": []}`。

无解时返回 `409`，指出**首个无法维持的关系**与**阻塞动作**：

```json
{
  "status": "infeasible",
  "stage": 1,
  "relationship": {"client_id": "billing-service", "endpoint_id": "api.example.com"},
  "blocking_action": "a3-remove-old-root",
  "reason": "untrusted_root",
  "chain": [
    {"cert_id": "leaf-old", "subject": "CN=api.example.com", "issuer": "CN=Old Root CA"},
    {"cert_id": "root-old", "subject": "CN=Old Root CA", "issuer": "CN=Old Root CA"}
  ],
  "trusted_anchors": ["root-new"],
  "message": "stage 1: relationship billing-service -> api.example.com loses its trust path; ..."
}
```

若初始状态本身就不满足约束，`status` 为 `invalid`、`stage` 为 `0`、
`blocking_action` 为 `null`。

### `POST /plans/verify` — 逐阶段回放任意计划

在同一场景负载上附加一个 `plan` 字段（见
[`examples/verify_request.json`](examples/verify_request.json)）：

```bash
curl -s http://localhost:8080/plans/verify \
  -H 'Content-Type: application/json' \
  --data @examples/verify_request.json
```

计划合法返回 `200 {"status": "valid", ...}`；否则在**第一个失效阶段**返回
`409`，包含失效关系、阻塞动作、断开的证书链（leaf-first）以及该客户端此刻的
信任锚，便于定位是「换证太早」「撤信太早」还是「动作排到了未授权的阶段」。

回放逐阶段进行：`action_ids` 为空的阶段是合法 no-op（空档），回放会信任状态
原样带入该阶段并在阶段结束后**继续校验全部信任关系**，因此空档无法掩盖此前
已发生的失效；响应会保留真实阶段号并原样回显空阶段。

计划结构要求：阶段从 1 开始连续编号（编号中允许 no-op 空档）；每个动作必须
且只能出现一次。

### `POST /plans/reconcile` — 中断后安全恢复点判断

部署在中途中断（编排器重启、部分动作结果未知）后，把**原始 PlanRequest**、
`/plans` **已生成的 stages**，以及对现场的**部分观测**一起提交，接口枚举所有
符合计划顺序、且与观测一致的可达进度，并给出在每个可能进度下都安全的下一步动作。
示例见 [`examples/reconcile_request.json`](examples/reconcile_request.json)：

```bash
curl -s http://localhost:8080/plans/reconcile \
  -H 'Content-Type: application/json' \
  --data @examples/reconcile_request.json
```

请求在场景字段之外额外携带：

| 字段 | 说明 |
| --- | --- |
| `stages` | 已生成的计划（与 `/plans` 输出同构）：阶段从 1 连续编号，每个动作恰好出现一次，允许 no-op 空阶段 |
| `anchor_observations` | 对客户端信任锚的部分观测：`{client_id, anchor_cert_id, present}`。`present: true/false` 表示**确实观测到**该信任边存在/不存在；**未上报的对象一律保持未知，绝不当作「未执行/不存在」** |
| `chain_observations` | 对端点当前链的部分观测：`{endpoint_id, chain}`（leaf-first）。未列出的端点保持未知 |

进度状态按以下规则枚举（至多 12 个动作，状态空间有界）：

- **已结束阶段必须完整执行**：第 1..p 阶段的全部动作都已生效；
- **当前阶段允许任意动作子集**：第 p+1 阶段的动作
  可能执行了任意子集（含空集），其中每个动作还必须在该绝对阶段号被允许、
  子集内不得有同锚的增信/撤信矛盾；
- **后续阶段不得提前执行**：更晚阶段的动作在当前状态中一律未执行；
- 剔除**已破坏通信关系**的状态（任何 required 关系失去信任路径即不可作为恢复点），
  以及**与观测不符**的状态。no-op 空阶段是真实的已结束阶段：推进
  `completed_stages` 计数但不改变信任状态。

进度的完整身份是 **(已完成动作集合, 已结束阶段数)** 二元组，而非动作集合
本身：空阶段原样跨过信任状态，因此同一组已完成动作可能处在空档两侧的不
同阶段位置（尚未跨过空阶段 / 已跨过空阶段 / 处于连续空档之间，含计划以
空阶段开头与尾部空阶段的情形）。这些位置是**不同的可达进度**，接口分别
保留——观测永远无法证明一个什么都没做的空阶段已被跨过，只保留较大的
`completed_stages` 会凭空引入确定性。观测过滤、完成态（`current_stage`
是否为 `null`）与冲突判断都使用该完整身份。唯一的归并例外是观测上等价
的情形：**非空**当前阶段的动作全部执行完，与「该阶段已结束、下一阶段尚
未开始」是同一个记账点，规范位置取后者。

成功返回 `200`，`possible_progress` 按
`(completed_stages, completed_action_ids)` 稳定排序，逐条给出已结束阶段数、
`current_stage`（全部完成时为 `null`）以及该进度下已完成的全部
`completed_action_ids`；`safe_next_actions` 只包含在**每一个**可能进度中都
①属于当前阶段、②尚未完成、③在该绝对阶段号被允许、且④**单独执行**后全部
通信关系仍有有效信任路径的动作（按 `action_id` 排序）：

```json
{
  "status": "ok",
  "safe_next_actions": ["a2-serve-new-leaf"],
  "possible_progress": [
    {"completed_stages": 1, "current_stage": 2,
     "completed_action_ids": ["a1-add-new-root"]}
  ]
}
```

例如观测到「新根已被信任、端点仍在提供旧叶」时，阶段 1 必然已结束、阶段 2
尚未开始；此时单独换证安全（新链由新根验证），但单独撤信会让旧叶失去信任路径，
因此 `safe_next_actions` 只推荐换证。计划全部完成时 `current_stage` 为 `null`、
`safe_next_actions` 为空。

当计划含 no-op 空阶段时，`possible_progress` 可能列出
`completed_action_ids` 相同但 `completed_stages` / `current_stage` 不同的
多条进度（空档两侧各一条）；`current_stage` 为 `null` 仅表示**所有阶段**
（含尾部空阶段）都已结束，而非仅所有动作已执行。推论：只要某个保留进度
的当前阶段仍是未跨过的空阶段，任何动作都不属于该进度的当前阶段，
`safe_next_actions` 即为空——此时唯一安全的做法是先让编排器推进
（跨过）空阶段，接口不会推荐任何动作。

**未知不等于未执行**：不带任何观测时，从「尚未开始」到「已全部完成」的所有
健康进度都会列出；观测到 `present: false`（锚确实不存在）才会排除「该增信已
执行」的状态——两者语义截然不同。

无任何兼容的健康进度时返回 `409`：

- `reason: "no_safe_reachable_state"`：与观测无关，符合计划顺序的状态本身全都
  破坏了某条关系（含初始状态即无效），无安全恢复点；
- `reason: "observation_conflict"`：观测联合排除了全部健康状态。`conflicts`
  按固定顺序（先锚 `(client_id, anchor_cert_id)` 后端点 `endpoint_id`）给出
  **首个不兼容的观测切片**（贪心：每个与此前幸存状态全部矛盾的观测都会列出），
  每条含 `kind`、定位字段、机器可读 `reason`
  （`anchor_present_mismatch` / `anchor_absent_mismatch` /
  `endpoint_chain_mismatch`）与 `message`：

```json
{
  "status": "conflict",
  "reason": "observation_conflict",
  "message": "the observations rule out every plan-ordered healthy state; ...",
  "conflicts": [
    {"kind": "endpoint_chain", "client_id": null, "anchor_cert_id": null,
     "present": null, "endpoint_id": "api.example.com",
     "chain": ["leaf-new", "root-new"],
     "reason": "endpoint_chain_mismatch", "message": "..."}
  ]
}
```

计划结构错误（阶段不连续、动作缺失/重复/未知、动作排在 `allowed_stages` 之外、
同阶段矛盾增撤信）或观测引用未知 id 时返回 `422`。

## 请求模型

| 字段 | 说明 |
| --- | --- |
| `certificates` | 全部证书：`cert_id`、`subject`、`issuer`、`not_valid_before`、`not_valid_after`（ISO-8601 时间，建议带时区；裸时间按 UTC） |
| `trust_anchors` | 计划开始前各客户端信任的锚证书 |
| `endpoints` | 每个端点的 `current_chain` 与 `target_chain`，**叶子在前、根在后**，末位必须是自签名根 |
| `relationships` | 必须始终保持有效信任路径的 client → endpoint 关系 |
| `actions` | 至多 **12** 个动作，每个动作声明 `allowed_stages`（可执行的阶段号集合） |
| `plan_time` | 计划时刻；缺省取当前 UTC。该时刻已过期或尚未生效的证书一律拒绝 |

动作类型：

- `add_trust`：`client_id` + `anchor_cert_id`
- `remove_trust`：`client_id` + `anchor_cert_id`
- `replace_cert`：`endpoint_id` + `new_chain`（必须等于该端点声明的 `target_chain`）

## 校验规则（422）

- 最多 12 个动作；`allowed_stages` 为正整数且不重复。
- 证书链不得成环（重复证书即视为成环）、签发关系必须逐跳吻合
  （issuer == 下一张证书的 subject）、必须以自签名根结束。
- 所有声明的证书在 `plan_time` 必须处于有效期内。
- 所有 id 引用必须存在；关系、信任锚、动作 id 不得重复。

## 本地开发

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8080
```

运行测试（含与暴力枚举的差分测试，120+ 用例）：

```bash
pip install pytest httpx
pytest -q
```
