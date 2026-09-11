# AegisAudit 分析报告

项目：对照池评测 20260911-093517

任务：6ef3f9c6-822d-4c8e-ae62-c913fa1ff0a6

状态：Partial

目标 SHA-256：f109924f0ee3ca5a80478d444ac6f0eaa250ea4acc668f1cd3a29a830ea2b4fc

结果快照 · 数据截至 2026-09-11T09:39:42.961Z · 导出时任务状态 PARTIAL。漏洞审计：PARTIAL；独立复核：PARTIAL；模糊测试：NOT\_RUN；运行验证：NOT\_RUN；利用验证：NOT\_RUN。静态复核不代表已在目标上验证漏洞或利用影响。

| 程序单元 | 文件 | 位置 / 地址 | 解析质量 |
| --- | --- | --- | --- |
| CopyModel | server/images.go | L665–L695 | PARSED |
| CreateLayer | server/images.go | L649–L663 | PARSED |
| CreateManifest | server/images.go | L531–L557 | PARSED |
| CreateModel | server/images.go | L251–L492 | PARSED |
| DeleteModel | server/images.go | L824–L853 | PARSED |
| GetLayerWithBufferFromLayer | server/images.go | L559–L577 | PARSED |
| GetManifest | server/images.go | L129–L154 | PARSED |
| GetModel | server/images.go | L156–L229 | PARSED |
| GetSHA256Digest | server/images.go | L1116–L1124 | PARSED |
| GetTotalSize | server/images.go | L120–L127 | PARSED |
| ParseAuthRedirectString | server/images.go | L1249–L1257 | PARSED |
| Prompt | server/images.go | L51–L82 | PARSED |
| PruneDirectory | server/images.go | L791–L822 | PARSED |
| PruneLayers | server/images.go | L756–L789 | PARSED |
| PullModel | server/images.go | L966–L1070 | PARSED |
| PushModel | server/images.go | L916–L964 | PARSED |
| SaveLayers | server/images.go | L500–L529 | PARSED |
| ShowModelfile | server/images.go | L855–L914 | PARSED |
| createConfigLayer | server/images.go | L1091–L1113 | PARSED |
| deleteUnusedLayers | server/images.go | L697–L754 | PARSED |
| formatParams | server/images.go | L580–L635 | PARSED |
| getLayerDigests | server/images.go | L637–L646 | PARSED |
| getValue | server/images.go | L1226–L1247 | PARSED |
| makeRequest | server/images.go | L1174–L1224 | PARSED |
| makeRequestWithRetry | server/images.go | L1128–L1172 | PARSED |
| pullModelManifest | server/images.go | L1072–L1089 | PARSED |
| realpath | server/images.go | L231–L249 | PARSED |
| removeLayerFromLayers | server/images.go | L494–L498 | PARSED |
| server/images.go | server/images.go | L1–L1279 | PARSED |
| verifyBlob | server/images.go | L1261–L1279 | PARSED |

## 审计策略与优先级

对 server/images.go 这一 Go 单模块（29 个函数）进行静态结构规划：先看模块级外部输入与信任边界（HTTP/注册表/文件路径/认证令牌），再按“用户可控输入→路径拼接→文件读写/删除→摘要校验”这条链排序，最后覆盖内存/索引操作与错误处理缺陷。工具方面：Semgrep 未运行、未构建未执行、无二进制恢复数据，故全部结论仅为待验证候选线索，需在后续逆向/语义审计阶段用原始行证据确认。

1. u\_6f87d34729e82d7261bb62ed0e05df5e：模块单元，包含执行/文件路径/身份权限/内存索引四类边界线索；含 Authorization Bearer 头设置与 sha256 使用点，是全局信任边界的入口，应先建立整体调用与数据流视角。
2. u\_a2333dfc668b28c3f639269e04d6df38：文件与路径边界加内存/索引线索的最大函数（251-492），调用 GetManifest、verifyBlob 等被标记单元，模型创建路径是外部输入进入文件系统的关键汇聚点。
3. u\_61f0ccfbc91aa1570b540f8178ae3cbb：realpath 一行式路径归一化函数；若路径拼接缺少规范化/越界检查，将直接影响 GetModel/CreateModel 的写入位置，需核实其是否约束到模型根目录。
4. u\_f0487c2bba4867a55e836c564d687643：GetModel 属文件与路径边界并调用 GetManifest；模型名来自外部请求，需确认路径构造是否可逃逸出预期目录。
5. u\_64b9b31b69a1fac7b8879423844165ac：GetManifest 读取清单、做 sha256 摘要并 json.Unmarshal；调用者众多（GetModel/CreateModel/DeleteModel/PushModel/PullModel），是校验缺失与反序列化信任的核查点。
6. u\_e77dbfc2c222d6538e603dd32f7e6868：ParseAuthRedirectString 解析 WWW-Authenticate/Bearer 重定向串并调用 getValue；注册表返回的认证头属外部不可信输入，解析逻辑与凭据处理是本目标最直接的身份权限边界。
7. u\_8d4d33cb226556c543ebd5cacdd6e7df：makeRequest 设置 Authorization: Bearer 令牌、处理代理与 client.Do；令牌来源、是否跨主机重发、代理环境变量信任需核实。
8. u\_26f2dab9592bea3ba44f5e7ed1dea982：makeRequestWithRetry 调用 makeRequest 与 ParseAuthRedirectString，是认证重试/重定向流程的控制点，可能把凭据重放到重定向目标。
9. u\_bcb20c0375fb7cd189ff981a9e93c578：PullModel 从远端下载、os.WriteFile 落盘并根据 sha256 摘要校验后再写清单；远程内容的完整性与路径来源是关键信任边界。
10. u\_ea1a5e27faece5e3b316208c4d65c32d：verifyBlob 通过 GetSHA256Digest 校验本地 blob，是防止篡改/摘要不匹配的最后一道校验，需确认校验失败是否真正阻断并可绕过。
11. u\_1016b68edaa534be224ae21974162908：PushModel 身份或权限边界线索，向上传流程外发模型数据与凭据，需评估鉴权与作用域约束。
12. u\_df0fae07f511c7cddc0b6ebec11ed1ca：GetLayerWithBufferFromLayer 兼具路径边界与内存/索引操作，读取层数据到 buffer 的大小与路径处理需核实。
13. u\_fe87b0a39af792ff87688cad50e3daa5：PruneDirectory 直接操作目录（文件与路径边界），递归清理逻辑若拼接不当可能删除预期外内容。
14. u\_aa0e87ddab18348f1144edaeb9e66529：DeleteModel 调用 GetManifest 并触发删除，属高影响文件系统操作，应确认删除目标由外部输入的最终解析结果决定。
15. u\_90aed18bc23dec903b4fbfb8ad470b6a：CopyModel 文件与路径边界，源/目标均可能来自请求参数，需核对是否存在路径穿越或覆盖。
16. u\_0f8df5bd7ec7a8245169cb29b066f51e：PruneLayers 依据 blob 名 sha256: 前缀与 ReplaceAll 生成标识，索引/命名解析错误会导致误删或残留。
17. u\_d97655047a00a2fca91daa4e5f5137e8：deleteUnusedLayers 计算引用并删除未使用层，是索引一致性与误删风险的核心；被 PullModel/CreateModel 调用。
18. u\_dcbfce14fd33500c1e34a4efe3fbd8f3：ShowModelfile 含执行或解释边界加内存索引线索，输出 Modelfile 可能涉及模板/指令内容的暴露与解释。
19. u\_384c87531b6e7d5fd538705ae7f5dfc9：SaveLayers 带内存/索引操作线索，层保存顺序与路径写入需核实一致性。
20. u\_89cb27b29d627fd12c0656b3961b3f02：GetSHA256Digest 内部使用 log.Fatal 而非返回错误，错误处理路径异常；作为校验基础函数被多处调用，缺陷会削弱完整性校验。
21. u\_b9659aec31fae248c4a805cef16150a6：createConfigLayer 序列化配置并计算 sha256，内存/索引线索；配置内容来源与摘要绑定需核实。
22. u\_ef57964a72f86839ca443d1ceb03de8a：Prompt 带执行或解释边界线索，提示构造可能影响后续模板解释或命令执行语义。
23. u\_2e7bf102aadfd435471040351f09f874：formatParams 对参数做格式化，参数很可能来自外部请求，是解释/注入类问题的前置处理点。
24. u\_e2b79b9c46505c1e0a48c29376e019b5：getLayerDigests 解析层摘要列表，索引解析结果直接影响 Pull/Push/删除的层选择。
25. u\_9342c1068edf1d9ea06bfa07fe7eefd4：CreateLayer 计算摘要并 Seek 文件，被 CreateModel 多处调用，是层落盘与元数据一致性的支点。
26. u\_dfab9deefc271cfbd0f2ba3e07244e8c：GetTotalSize 属规模计算路径，虽无线索但与磁盘配额/资源消耗相关，作为低优先核算项。
27. u\_980bd040a2be577204c6ddb3372e62e9：pullModelManifest 获取远端清单，是 PullModel 的信任入口前置，需与后续校验比对。
28. u\_c910d2dcbe5ec73183ae510d9646ded4：getValue 为认证头解析的底层辅助函数（被 ParseAuthRedirectString 多次调用），其健壮性影响凭据解析。
29. u\_56d2923f31fc0bae88b4bd268610e2ce：CreateManifest 写出清单文件，与 GetManifest 的校验形成闭环，属次要但需确认写入内容与来源一致。
30. u\_b7ef22ecc463d7560956c6745c7764eb：removeLayerFromLayers 修改切片/索引（无线索但被删除流程依赖），用于确认索引操作是否存在越界或误删。

规划限制：调用图不完整（call\_graph\_complete=false），候选中的推断边与未解析调用按近似处理，不能据此断定可达性。

规划限制：Semgrep 未运行（Windows 原生执行器未准备），仅有内建词法线索；词法线索不代表漏洞，需独立语义验证。

规划限制：未实际构建或运行目标（target\_executed=false、build\_executed=false），无运行时/动态证据；所有路径、认证与删除行为的实际可达性未知。

规划限制：本目标为 SOURCE 且无二进制恢复数据，无法评估加壳/混淆/反编译质量；不得声称发生了脱壳或反混淆。

规划限制：run\_config 缺少构建系统、启动入口与依赖清单，HTTP/gin 入口来自静态识别，真实路由与中间件鉴权链未确认。

规划限制：人类标注为空，无外部可核对信息；所有结论须以原始源码行证据与后续复核为准。

规划限制：动态分派、接口实现与部署配置（注册表地址、代理环境变量、运行用户权限）未知，留作显式缺口。

## 发现与复核

静态结论范围：COMPONENT

### CreateModel 中 MODLEFILE 的 model/adapter 路径未经约束直接打开本地文件（可读任意路径）

CWE-22 · MEDIUM · 复核 VALIDATED · 验证 NOT\_RUN

输入：parser.Command.Args（MODEL/ADAPTER 指令的路径字符串，见 251 行参数 commands）

危险操作：os.Open\(realpath\(c.Args\)\) 打开任意本地文件并交给 CreateLayer/llm.DecodeGGML 读取（279、375 行）

防护缺口：缺少受控基目录校验（如将路径限制在允许的模型目录内）、缺少对 \`..\`/绝对路径/符号链接的拒绝或规范化后白名单校验

前提：调用方能控制 Modelfile 指令内容；进程对该路径具有读权限；若经由 HTTP 接口触发，还需该接口对客户端开放且无可信目录约束

影响：任意本地文件读取（内容被读入模型层并可能随 manifest/层持久化或经错误/日志侧信道泄露），以及由超大/特制文件触发的资源耗尽

修复：在 279/375 行打开文件前对路径做规范化并校验其位于显式允许的基目录内，或仅接受通过 GetBlobsPath 解析出的摘要式 blob 引用；拒绝绝对路径、\`..\` 段与逃逸出基目录的符号链接

- 证据：server/images.go L279–279 ；产物 e070006a-77ec-45c2-b901-b987423253e8；引用：			bin, err := os.Open\(realpath\(c.Args\)\)
- 证据：server/images.go L375–375 ；产物 e070006a-77ec-45c2-b901-b987423253e8；引用：			bin, err := os.Open\(realpath\(c.Args\)\)
- 证据：server/images.go L270–277 ；产物 e070006a-77ec-45c2-b901-b987423253e8；引用：			if strings.HasPrefix\(c.Args, &quot;@&quot;\) { 				blobPath, err := GetBlobsPath\(strings.TrimPrefix\(c.Args, &quot;@&quot;\)\) 				if err \!= nil { 					return err 				}  				c.Args = blobPath 			}
- 证据：server/images.go L231–248 ；产物 e070006a-77ec-45c2-b901-b987423253e8；引用：func realpath\(p string\) string { 	abspath, err := filepath.Abs\(p\) 	if err \!= nil { 		return p 	}  	home, err := os.UserHomeDir\(\) 	if err \!= nil { 		return abspath 	}  	if p == &quot;~&quot; { 		return home 	} else if strings.HasPrefix\(p, &quot;~/&quot;\) { 		return filepath.Join\(home, p\[2:\]\) 	}  	return abspath

复核 v2（MODEL，VALIDATED）：在本组件（CreateModel）边界上，commands \[\]parser.Command 是调用方提供的符号化参数，未经任何受控基目录约束即进入文件系统操作：循环第 264 行逐条读取 c.Args，case &quot;model&quot; 仅对以 &#39;@&#39; 开头的参数经 GetBlobsPath 做 blob 摘要解析（251/264-279），非 &#39;@&#39; 路径直接 os.Open\(realpath\(c.Args\)\)；case &quot;adapter&quot; 更是无条件 os.Open\(realpath\(c.Args\)\)（373-375）。realpath 只做 filepath.Abs 与 &#39;~&#39; 展开（U0006 231-248），不做根目录限制、不拒绝 &#39;..&#39;、绝对路径或符号链接逃逸。因此调用方传入的任意可读路径（如 /etc/shadow）都会被打开并交给 llm.DecodeGGML/CreateLayer 读取，构成组件级任意本地文件读取。

反证：已考虑 realpath 作为“路径净化”的可能防御，但它仅是 filepath.Abs + &#39;~&#39; 展开，无任何白名单/基目录约束（U0006 231-248）；已考虑 &#39;@&#39; 前缀经 GetBlobsPath 的摘要校验（U0007 270-271），该防御只覆盖以 &#39;@&#39; 开头的形参，不覆盖普通路径；os.Open 失败后回退到模型引用解析（281-297）只改变后续流程，不能阻止已成功的越权打开；也未发现对 c.Args 做 filepath.Clean、strings.Contains\(&quot;..&quot;\) 或前缀校验的代码。

待补信息：本单元快照外是否已有上层（如 /api/create 路由、Modelfile 解析器）对提交的路径做白名单或目录限制，无法从快照确证；被读文件必须存在且进程具备读权限（属组件普通前置条件）。本结论为组件级静态判定，不构成对完整部署服务的已利用结论。
静态结论范围：COMPONENT

### CreateModel 对 \`@\` 前缀参数直接作为 blob 键解析，未校验摘要格式

CWE-22 · UNKNOWN · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：c.Args 以 \`@\` 开头时的后缀字符串（270-277 行）

危险操作：GetBlobsPath\(strings.TrimPrefix\(c.Args, &quot;@&quot;\)\) 解析文件系统 blob 路径（271 行），结果随后在 279 行被 os.Open

防护缺口：缺少对传入 GetBlobsPath 的字符串做摘要格式校验（十六进制/固定长度白名单）；是否在下游实现校验未知

前提：GetBlobsPath 未对输入做字符白名单或路径拼接校验，且其内部存在路径拼接/目录遍历

影响：若下游 GetBlobsPath 直接拼接路径，则可读取或探测预期的 blob 存储目录之外的文件

修复：在 271 行调用前校验入参必须匹配预期的摘要格式，或让 GetBlobsPath 自身将输入限制为非 \`..\`/无路径分隔符的固定字符集，并复核其实现

- 证据：server/images.go L271–271 ；产物 e070006a-77ec-45c2-b901-b987423253e8；引用：				blobPath, err := GetBlobsPath\(strings.TrimPrefix\(c.Args, &quot;@&quot;\)\)

复核 v2（MODEL，INCONCLUSIVE）：第 271 行确实把 CreateModel 的入参 c.Args（以 @ 开头时）经 strings.TrimPrefix 后传给 GetBlobsPath，随后 c.Args 被改写为返回值并在 279 行进入 realpath\(\)+os.Open，因此入参到 GetBlobsPath 的局部数据流成立。但候选主张的危险汇聚点（路径拼接/目录遍历/是否限定在 blob 存储目录）位于 GetBlobsPath 内部，而该函数在本快照中没有任何定义或实现可读（search\_code 对 GetBlobsPath / func GetBlob 均无定义命中，inspect\_target 显示仅有 server/images.go 一个代码文件，函数级调用图中该调用也被标为 UNKNOWN），因此无法证明其是否做了摘要格式/字符白名单校验或是否真的与目录拼接。同快照中可见的 realpath（U0006，231-248）只做 filepath.Abs / ~ 展开，不含任何目录包含性校验，但它是通用路径归一化，不能替代 GetBlobsPath 的未知实现。另有反证性事实：即使保留原始 c.Args（不带 @）也会在 279 行 os.Open\(realpath\(c.Args\)\)，说明“打开调用方给出的文件路径”本身是本组件声明的功能（本地模型文件/引用），要构成穿越必须另有“限定于 blob 目录”的信任边界，而该边界仅存在于未提供的下游代码。综上所述，静态证据不足以确认或否定该 CWE-22 主张。

反证：1\) realpath（U0006 231-248）在 279 行之前被调用，但它只做 filepath.Abs 与 ~ 展开，既不阻止也证明了目录穿越；2\) 279-282 行在 os.Open 失败时把 c.Args 当作模型引用解析（ParseModelPath/PullModel），说明按路径打开文件是本组件的既定功能语义；3\) GetBlobsPath 在其他多处被用于 manifest/layer 的 sha256 摘要（如 172、300、324、503、560、1262 行），提示其语义是“按摘要定位 blob”，但这是用法推断，不能当作实现对非法输入做校验的证据。

待补信息：GetBlobsPath 的定义/实现完全缺失（单文件快照与结构分析均未包含），因此无法判断：\(a\) 它是否对入参做 sha256 十六进制/长度白名单或 base 分隔符过滤；\(b\) 它是否用 filepath.Join 与 blob 根目录拼接并是否做包含性校验；\(c\) 该分支的 c.Args 在实际部署中是否完全由外部请求体控制。此外，若 GetBlobsPath 实际只做校验并返回错误，本条应为 REJECTED；若确实裸拼接，则需进一步评估读取范围。
静态结论范围：COMPONENT

### 图层摘要未经校验直接拼接为文件路径（潜在路径穿越）

CWE-22 · HIGH · 复核 UNREVIEWED · 验证 NOT\_RUN

输入：GetModel\(name\) 的 name → ParseModelPath → GetManifest 返回的 manifest.Layers\[\].Digest（第 171 行遍历、第 172 行取值），其内容源自磁盘上的 manifest 文件，最终可溯源到远端注册表/OCI 清单。

危险操作：第 172 行 GetBlobsPath\(layer.Digest\)，随后第 188/195/202/209/220 行对返回的 filename 执行 os.ReadFile / os.Open。

防护缺口：未见对 layer.Digest 做格式白名单校验（如 ^sha256:\[a-f0-9\]{64}$），也未见对拼接结果做路径前缀归属校验（须位于 blobs 根目录内）；GetBlobsPath 本身是否含 filepath.Base / Clean / 前缀断言无法确认。

前提：攻击者能影响被读取清单的 Layers\[\].Digest 字段（例如通过拉取/导入由攻击者控制的模型清单），且 GetBlobsPath 未做路径规范化与根目录约束。

影响：可越权读取进程可访问的任意文件（如模板/系统提示内容经 model.Template、model.System、model.License 回传），造成敏感文件泄露或后续基于读取内容的行为操纵。

修复：在使用前用正则强制校验摘要为 sha256 十六进制格式；在 GetBlobsPath 内使用 filepath.Clean 并用 filepath.IsLocal / 前缀断言确保结果位于 blobs 根目录内，拒绝任何含分隔符或 .. 的输入。

- 证据：server/images.go L172–172 ；产物 e070006a-77ec-45c2-b901-b987423253e8；引用：		filename, err := GetBlobsPath\(layer.Digest\)
- 证据：server/images.go L171–175 ；产物 e070006a-77ec-45c2-b901-b987423253e8；引用：	for \_, layer := range manifest.Layers { 		filename, err := GetBlobsPath\(layer.Digest\) 		if err \!= nil { 			return nil, err 		}
- 证据：server/images.go L188–192 ；产物 e070006a-77ec-45c2-b901-b987423253e8；引用：			bts, err := os.ReadFile\(filename\) 			if err \!= nil { 				return nil, err 			} 
- 证据：server/images.go L209–212 ；产物 e070006a-77ec-45c2-b901-b987423253e8；引用：			params, err := os.Open\(filename\) 			if err \!= nil { 				return nil, err 			}
- 证据：server/images.go L158–158 ；产物 e070006a-77ec-45c2-b901-b987423253e8；引用：	manifest, digest, err := GetManifest\(mp\)
- 证据：server/images.go L149–153 ；产物 e070006a-77ec-45c2-b901-b987423253e8；引用：	if err := json.Unmarshal\(bts, &amp;manifest\); err \!= nil { 		return nil, &quot;&quot;, err 	}  	return manifest, shaStr, nil
静态结论范围：COMPONENT

### 按清单摘要读取 blob 内容时未验证 blob 内容与摘要一致

CWE-345 · MEDIUM · 复核 UNREVIEWED · 验证 NOT\_RUN

输入：manifest.Layers\[\].Digest 与本地 blob 文件（由第 172 行 GetBlobsPath 得到路径）。

危险操作：第 188、195、202、209、220 行 os.ReadFile / os.Open 读取 blob 并把内容写入 model.Template / model.System / model.Options / model.License。

防护缺口：读取前后没有对文件内容重算摘要并与 layer.Digest 比较，也没有对 manifest 做签名/来源校验；即内容完整性绑定缺失。

前提：本地 blob 存储可被非特权或旁路方式篡改，或存在并发写入窗口（TOCTOU）。

影响：被篡改的模板/系统提示/参数字节会被当作可信模型元数据加载，可导致注入到推理提示或参数污染。

修复：读取后重算 sha256 并与 layer.Digest 常量时间比较，不匹配则拒绝加载；对清单引入签名或受信来源校验。

- 证据：server/images.go L188–193 ；产物 e070006a-77ec-45c2-b901-b987423253e8；引用：			bts, err := os.ReadFile\(filename\) 			if err \!= nil { 				return nil, err 			}  			model.Template = string\(bts\)
- 证据：server/images.go L216–218 ；产物 e070006a-77ec-45c2-b901-b987423253e8；引用：			if err = json.NewDecoder\(params\).Decode\(&amp;model.Options\); err \!= nil { 				return nil, err 			}
- 证据：server/images.go L146–153 ；产物 e070006a-77ec-45c2-b901-b987423253e8；引用：	shaSum := sha256.Sum256\(bts\) 	shaStr := hex.EncodeToString\(shaSum\[:\]\)  	if err := json.Unmarshal\(bts, &amp;manifest\); err \!= nil { 		return nil, &quot;&quot;, err 	}  	return manifest, shaStr, nil

## 关键逻辑与人工修订

- u\_64b9b31b69a1fac7b8879423844165ac · CRYPTOGRAPHY · v1（MODEL）：GetManifest 对清单字节调用 sha256.Sum256 并用 hex 编码生成内容摘要，属于完整性散列用途（非口令散列），无密钥、无 HMAC，不能证明来源真实性。
  - 原文：server/images.go L146-L147；	shaSum := sha256.Sum256\(bts\) 	shaStr := hex.EncodeToString\(shaSum\[:\]\)
- u\_6f87d34729e82d7261bb62ed0e05df5e · AUTHENTICATION · v1（MODEL）：U0001 第31-36行定义的 RegistryOptions 同时声明 Token、Username、Password 三种注册表凭据字段，并以明文结构体字段形式在本模块内传递，没有过期时间、作用域或存储保护字段；凭据的实际使用位于被委派的 makeRequest（U0027）与 makeRequestWithRetry（U0026）函数体内，需在对应任务中判定其传输与复用是否安全。
  - 原文：server/images.go L31-L36；type RegistryOptions struct { 	Insecure bool 	Username string 	Password string 	Token    string }
- u\_89cb27b29d627fd12c0656b3961b3f02 · CRYPTOGRAPHY · v1（MODEL）：GetSHA256Digest（U0025，第1116-1123行）用 crypto/sha256 对 Reader 内容计算摘要并输出 &quot;sha256:&lt;hex&gt;&quot; 字符串，是层内容与清单一致性校验的基础原语；其调用点包括 verifyBlob（U0030）与 CreateLayer（U0014），摘要值随后被直接用作 blob 路径与比较依据，故该摘要函数的安全性（含第1119-1121行 io.Copy 失败时 log.Fatal 终止进程）需单独复核。
  - 原文：server/images.go L1116-L1123；func GetSHA256Digest\(r io.Reader\) \(string, int64\) { 	h := sha256.New\(\) 	n, err := io.Copy\(h, r\) 	if err \!= nil { 		log.Fatal\(err\) 	}  	return fmt.Sprintf\(&quot;sha256:%x&quot;, h.Sum\(nil\)\), n
- u\_8d4d33cb226556c543ebd5cacdd6e7df · AUTHENTICATION · v1（MODEL）：makeRequest（U0027，第1188-1194行）以 regOpts.Token 非空为准设置 &quot;Authorization: Bearer &lt;token&gt;&quot;，否则退回 SetBasicAuth；同时第1175-1177行允许依据 regOpts.Insecure 把请求方案改写为 http，凭据是否可能在明文信道传输取决于调用方（U0022/U0026）传入的 Insecure 与注册表地址，需在对应任务确认。
  - 原文：server/images.go L1188-L1194；	if regOpts \!= nil { 		if regOpts.Token \!= &quot;&quot; { 			req.Header.Set\(&quot;Authorization&quot;, &quot;Bearer &quot;+regOpts.Token\) 		} else if regOpts.Username \!= &quot;&quot; &amp;&amp; regOpts.Password \!= &quot;&quot; { 			req.SetBasicAuth\(regOpts.Username, regOpts.Password\) 		} 	}

## 覆盖与错误

```json
{
  "audit_config": {
    "max_model_calls": 400,
    "max_output_tokens": 0,
    "max_tool_rounds": 12,
    "max_units": 40,
    "model_timeout_seconds": 900,
    "reasoning_effort": "high",
    "timeout_seconds": 3600
  },
  "audit_coverage_gap": "共 30 个可读单元，完成 4 个单元的语义审计；其余未审计",
  "audited_unit_count": 4,
  "edge_count": 336,
  "eligible_unit_count": 30,
  "exclusions": [],
  "files": [
    {
      "language": "go",
      "path": "server/images.go",
      "reason": "",
      "status": "PARSED",
      "unit_count": 30
    }
  ],
  "finding_count": 4,
  "function_count": 29,
  "fuzzing": "NOT_RUN",
  "incomplete_agent_tasks": 1,
  "independent_review": "PARTIAL",
  "metadata": {
    "analysis_scope": "STRUCTURE_ANALYSIS",
    "call_graph_complete": false,
    "code_file_count": 1,
    "function_count": 29,
    "module_count": 1,
    "semgrep": {
      "reason": "执行器未准备 Windows 原生 Semgrep 1.176.1；使用内建线索并进行独立语义审计",
      "status": "UNSUPPORTED"
    },
    "target_sha256": "f109924f0ee3ca5a80478d444ac6f0eaa250ea4acc668f1cd3a29a830ea2b4fc",
    "verification": "NOT_RUN",
    "vulnerability_audit": "NOT_RUN"
  },
  "model_usage": {
    "calls": 73,
    "cost_cny": null,
    "measured_tokens": 441686,
    "unknown_usage_calls": 0
  },
  "result_artifact_id": "e070006a-77ec-45c2-b901-b987423253e8",
  "reviewed_finding_count": 2,
  "structure_partial": false,
  "tools": [
    {
      "command": [],
      "details": {
        "execution": "IN_PROCESS",
        "max_source_bytes": 2097152,
        "per_file_timeout_ms": 1000
      },
      "exit_code": null,
      "finished_at": "2026-09-11T09:35:19.670Z",
      "log_artifact_id": "",
      "name": "tree-sitter",
      "started_at": "2026-09-11T09:35:19.642Z",
      "terminated": false,
      "version": "0.25 (grammars pinned in Cargo.lock)"
    }
  ],
  "unit_count": 30,
  "unresolved_calls": 295,
  "verification": "NOT_RUN",
  "vulnerability_audit": "PARTIAL",
  "warnings": []
}
```

任务错误：智能体响应再次未通过校验：智能体结果结构无效：invalid type: sequence, expected a string

## 证据产物

- aegis-report-6ef3f9c6-822d-4c8e-ae62-c913fa1ff0a6.html；ID：72786b29-7144-499d-9967-5fec40d0083e；SHA-256：32c17f3e764716de096a7db0f198680e317904a2a593a926954722bb47be95f9
- aegis-report-6ef3f9c6-822d-4c8e-ae62-c913fa1ff0a6.json；ID：dcea3d81-5d67-4d71-9011-317d3cafdb63；SHA-256：c9cc0230070a0abd647faed1a10fb1392fb9db3693f8b0f464c743257f65f8b5
- agent-AUDITOR-116506fd-aef6-4a5a-b8ae-f4bdd92dd414.json；ID：e38d8fba-fedc-4ad9-9fab-98f41d17a9f6；SHA-256：7b13361e41a7980f5816a0392b73031eaebe021e0f3748c1b666cbce65258a4c
- agent-AUDITOR-22ec7202-9606-4b43-bc62-c3ff8c74e3ae.json；ID：1bbcd674-213c-457f-ae90-6caba3e52195；SHA-256：bbeb33bb6f76de577208475136c9d9a4da7ccdec002c6774f1837c4d419e4945
- agent-AUDITOR-cf80ed01-e7da-4b90-928e-833534f30993.json；ID：10bd4f09-942c-4637-b386-be30e53d4479；SHA-256：a0012f9db198235033c42dd7f102250771dcd9d3f46043623eadc9dddad7acf5
- agent-AUDITOR-e824c90d-1dc7-4cee-8a2e-142922b02695.json；ID：661681fd-0274-4a0a-a54f-b5d3b9bb0faf；SHA-256：ae22db0d7f98553c168c4bb36fd927277b233b6a5bf881140e386482ef8de18a
- agent-PLANNER-0016173a-796b-4028-a9cc-34d28045d47b.json；ID：292642b9-8b19-47e0-afb1-5c0a0ac9b45e；SHA-256：c380664faa745f4609074561c17bbb7c963bf35835ffd8f155f99964ac760bb1
- agent-REVIEWER-8e319725-0ad7-46ff-a356-6b31c5bab0b6.json；ID：4dfb5548-f719-4053-835f-e5648685a1cc；SHA-256：2c6d8c3f1256486dddf504fd8e1da09e8867e8039620818555c0d896adaa9c5e
- agent-REVIEWER-e41fdb89-1d12-4069-b820-e84c4bfad309.json；ID：d61f7429-fbf1-47a3-9920-d0235c89c7d6；SHA-256：f0afe5368b963e95214f8c0147b3667fb89809d1546e4c13cb19366f94573dd8
- analysis-result.json；ID：e070006a-77ec-45c2-b901-b987423253e8；SHA-256：89014ec329ebeac9f931a454fa483427db79586b9d5b84e00f4474e44e729caf
- model-request-000bdf8c-3590-4a1a-bc46-7a6e6b1ddbf6.json；ID：f59c948a-531a-40a6-a6d0-57fca6af3fe0；SHA-256：e0ae6516e6702effba3ebe77657e56111b150730463051d09adcc21b03e7d994
- model-request-02343bfb-f18a-4d3b-8b52-adee1b9d3345.json；ID：6bb7a7ef-0dd4-4d25-8ee7-f31e93135297；SHA-256：bd49364289efd5f1793ea13a59c16d4b19cf1f2ca14801f87e8f4040fe9f3cfc
- model-request-0df79a63-2cdd-4269-b44c-06757a3a55a4.json；ID：172abfe2-687b-4cc8-b01c-569184dbe8ce；SHA-256：12e9060469c5815ed3110adf07aeec1143393c62d20d6d8f451fbce97d90c23f
- model-request-0f990e02-987b-469a-bcce-f692ca62a0a9.json；ID：bdfff69a-e7ec-4f54-8122-3638bc542b68；SHA-256：3b29452f89a645fb97db6bbe84c330593e263283f8dfce45745da5b8b55d70fe
- model-request-14937ba1-7be2-44d5-8ebe-2c1cca686213.json；ID：0d734799-6694-4441-be61-d4ee31aeb08f；SHA-256：5106569973e6ff42918e446cda6737a06fc102a583fad8a7ccdb080f62aa5a84
- model-request-1e25a539-085d-4b13-9b67-3bbf9cb0a483.json；ID：12b4e99f-a430-42c1-b09d-fcece93b90d2；SHA-256：34baa03c68d8b2ab898b69d7dae979ed0c72a88db99cee51d29d1696d2e9ac8d
- model-request-1e65dfad-6bac-4e21-ac70-03a7c28f2e11.json；ID：62801a3e-0203-47a0-aabd-c23837cc3ae3；SHA-256：9867b5e12ab0dded0f990e2e966d6eaa65181defcb6da62f8051a1152d33ef52
- model-request-1fea6f06-61a3-47bb-a4cb-b3e39b5a9bd9.json；ID：e5794ec4-9590-4923-9318-bc6aea1f7fc8；SHA-256：bca9953a3153286f716df0a1eac782295620fa038e7f0dc49b06e9fbd8d22994
- model-request-241c8393-d4df-4729-9955-059795ca47c3.json；ID：50878272-ae50-4eb2-a3fe-a73cb1a8474d；SHA-256：c84bb2feef6c24fd65a93bb5a191ded2c9538e30204b1c9473c748eb492cd97b
- model-request-25b06f9c-80ac-4634-b5e3-3f6a8a0e0af1.json；ID：be6cb658-e9ad-451e-b8e4-409179f26f28；SHA-256：77fbee1366365bb2b97540a3a85d4853db6677b67d3183c96465686aa3e76754
- model-request-25b6b822-1078-4706-8c39-87607332d1ab.json；ID：4091d688-6bd3-40d7-89b8-2a39b3a8a567；SHA-256：d2bb52dcbfad7b0255951f1767ecb276d489efdfaa082057eba6b5490d2414ee
- model-request-349f8eb7-5145-465a-a5a1-67c847c3fbcd.json；ID：780b5949-f34d-4b80-9d32-17086b3a4800；SHA-256：984b8d54aab280051ff59b5a7b0251cd946c8237571cdc742ffc19408365b21e
- model-request-34f91305-5d9b-4982-aa75-47e94bf44748.json；ID：c561c2ef-219b-4107-baea-902dc3a4a8dc；SHA-256：ece8800d186f29cbed73082c0fc6ae634ceb6ab61cafbe3d28ee6f4c78fda108
- model-request-35077e55-898b-4d64-818d-ab877a6a6cb3.json；ID：5b011613-3530-48ab-889f-779bd6ad4459；SHA-256：7c25b0ccea821565ef8778db88b9daaea72f110107dfcf4a72243e89dc152c29
- model-request-3b707d87-c971-4a7d-98e2-4eec4c5fe5f9.json；ID：8ecfbccd-3259-4100-a856-c8ab4c6c2a4e；SHA-256：3db34d626f0cf1044cceea07c7f94d544d943960c9a2081789260a09a6ca55a1
- model-request-3c97f7ea-05d5-423b-aa52-a989cba733cb.json；ID：3240a08d-4258-4dec-afaf-7b3f9538008a；SHA-256：2d65d6c4db801a6734bba7aeab6cb7baf3156f1513c93538d25948446e196e5b
- model-request-3cff9a85-a143-43f5-bc67-3459d5f3c957.json；ID：f31030fe-181f-4046-a7f1-7b78b55c09ad；SHA-256：b6fd4dd1825fcca86793342264631b5323e2325eedf78f2d9402590ac3f72248
- model-request-40c64d87-63bc-4c9f-9e1c-2185d00faee5.json；ID：5712af45-8433-4506-9504-437bb1b86ce9；SHA-256：99f4a0ff3a5cc17ccf869e64b358b848cc172567a04fd7b362c91bf1f3686896
- model-request-45eee19d-0f17-49a2-b1a5-c3b187b27290.json；ID：034b327b-7400-49d5-8280-8b0e66ff3f2b；SHA-256：f854d34ecfa513ec7aa6e9bd657d813fe75eb07ddb35d95225d8c435975fc572
- model-request-4b4679e3-8dc8-47dc-95d4-6052983243ac.json；ID：a2155f26-95fd-4540-adde-cb7a92ce2a29；SHA-256：5bf08b618380197e25014901760dbfddf5c315fd4963a8b95030786092a5dc92
- model-request-4e78e216-8fd6-4132-8be8-b9896b87fb0b.json；ID：abb082f2-d05c-4e39-96b1-b7d35d3dab37；SHA-256：53be7dd4e79788a58a6ba52dabf73e38cbae971b704c108527d7cd90cffe63ea
- model-request-57ce3f46-440a-4f7f-856a-dc54eee5d824.json；ID：501a6561-c00f-4041-ae42-443e89c725c7；SHA-256：bbf58b6b0985f6c80eafb9d024d32fc0c700a1470a745c4c6d29d0cc89757e4d
- model-request-581c4345-946b-4473-b943-f696d8aaa955.json；ID：88f257eb-205c-4d37-b7d6-69127eb7eb1a；SHA-256：4a8b58a803293903023c031dc30ae6f5bd7d8d458480de74dc8e3f829bab6abf
- model-request-584e94c4-c0ca-41b4-81c0-8a895991fac9.json；ID：531dc821-964c-4eef-9dac-cf9799cf8d15；SHA-256：cfa4ad32f4a4823d493112c87b5694f367bb8560a8f00eb1c3efd1dfc2f3e75b
- model-request-5acc14f1-e576-42d9-b508-518702bdb592.json；ID：56a3d859-7845-4c91-bdf4-02322b43a783；SHA-256：4bd8b5d059a2d23ce9643dc6c5426456a23821bfe1b310ab670fb25562aed945
- model-request-5cb05df8-baf4-4453-b577-ce8ed3927158.json；ID：f07b1746-5989-4405-b36e-f81240486846；SHA-256：95c91eb9f38110d29003af9d32407ad6a4728e01a961575578f2020e608198ec
- model-request-60d0f67d-5c36-4aa3-953d-8bd27619375f.json；ID：fab619a6-e4df-4596-8a0f-de7dc414569d；SHA-256：22b0417d7d51fcc36d12e4cf46de1b3ff3b0a7b54e320f994a78546c647e7093
- model-request-62919812-6217-467d-9a9b-161a75da96ff.json；ID：08acc70f-02fd-4261-a247-20d1351fd578；SHA-256：b405bc1096587162dd9de1275e6a9c34d7f96863630ef52d905312c500bf1b13
- model-request-646563e1-cda4-4260-851b-b6a34fc05d03.json；ID：44f70aa6-2864-47f4-a6a2-4da570f8368a；SHA-256：debcf8f11d37929818eb35453ee6dee70962532be5953b27c7804983a3c7426e
- model-request-64d1b5c6-3743-49db-8cf1-2f8e94d479cb.json；ID：734f3045-b936-437f-8f78-6499e3fc464a；SHA-256：f9554215ce02b5df8b0f5222b144f007dd42dc7982822d1beede00e262475c19
- model-request-66956391-2ece-4614-8c17-2b7477a05aba.json；ID：b611fa6a-0365-49e3-857a-41f03a7a5b78；SHA-256：be3c73c8ce1013f056ba9aff9f97a12935af35b1c1857c1a25e15171831b9e13
- model-request-69d6820b-f541-4893-b356-16cc8c919a2a.json；ID：fadd3d1c-b705-43a9-8b37-e583b7719f40；SHA-256：ee64523d3171bf4047a485ade1117aa27404e3696b47535bf287f2bc098aa997
- model-request-75392b9d-e104-4d3f-bb0c-9e7fce19c972.json；ID：74d24fce-2923-4b7f-85e7-3c5a8cf6ae19；SHA-256：1d0c917f94c61b3c1a013d4e3ff21faa5dd253b320c70329fbef2d0e0372a5b0
- model-request-76455fb6-045a-49a9-8276-92a88e600fdb.json；ID：9cad62c0-69e9-4109-a1f7-1a5cbf1952f2；SHA-256：5ef3b89b6c47a4f6907366dc9e76eaad2353f371bc32d75965dfc4c85e2be412
- model-request-7f9114d7-5848-461a-b8e9-e1be44120b1d.json；ID：ea7c23c2-e9ca-43d1-bbea-1ba3d466b427；SHA-256：e730b493fd2ffe5b1979ae269833ab43adc7c6284de50aaf6b451d6f86244c75
- model-request-877f1f72-7fdc-4483-9130-cac2917c995b.json；ID：bfaf438a-7d21-4a32-96e9-6ac6466a4d9e；SHA-256：fe6250c6342c21f57b6d26ffdfe3f517f57495547000bc8c5a6ab8619ca3ae25
- model-request-94804384-a07b-4ebb-87b8-66dbba42f270.json；ID：97960b88-b69d-4322-9b62-ac09ae6ae94e；SHA-256：0bee0b74eb0c0ee5ad3316400f14cb10533666b7d51b95c64763551d149a3b95
- model-request-975f35eb-dd5a-448b-839a-ffabe9676eaf.json；ID：898dd16d-4810-4ee1-a81a-361d933a1c30；SHA-256：9acfaa847cfeb447404c15b890bbe7047e29bd819b149457a405f610d7679d3a
- model-request-9a05f090-9991-49e8-bb60-b315451d7626.json；ID：3178dc5c-deb4-4a32-8ae6-4467b15178f5；SHA-256：aac6bc40d53d35be878569aeb26d128775855d8a63af5d7c800db322e90fb20c
- model-request-9cb3378a-f0c8-4ee8-b83b-55a15e6ca312.json；ID：d8903057-ccc3-45e3-8d04-76dad05ff9b9；SHA-256：c3dc95543ce13e0f2a7b1ddaf5e07a0048a27e261359ea2813a33c2ebe438b96
- model-request-9d8843cb-3020-4a12-8fc9-2fe20d7a4571.json；ID：0f9144b5-3764-4f9b-8dd7-d3c6b15ad093；SHA-256：77b46f12dd86b923df8547d45872f2cb0323ce45aa507f3797fc6f23b10815ff
- model-request-9ed52c9a-2f01-4b09-a2b9-435c89797c1e.json；ID：38ed8b75-bd5a-450d-b69e-05b3eec95072；SHA-256：ac31a74952a65e36ed54498a5d6d70dbb39a5835828cae59d823830abc02dc4f
- model-request-a2027aa5-aa36-4b4e-a78f-84b904bb06a2.json；ID：093caddc-10f9-4ea5-b7a9-8be83dd18d2f；SHA-256：26f76272d82fe228ec1c1e3234f53837f9051aa7830f88a82c5be935eeb94d74
- model-request-a2a1e5ae-e52d-474c-8b39-1d002343aefd.json；ID：74c3d1c8-fe7f-49d6-868d-ec4ae6b8af6e；SHA-256：eee8488d776fa290b21383c506f73951d0608ee8cf5d2feb6d030cd72c826b9a
- model-request-a3d27883-3250-4b6f-8fc0-3b6f2d73f801.json；ID：1098fa88-f340-40d0-94d0-37d0fb41d3eb；SHA-256：461303b72fdeac94735a1fa433253788854b961856f95362fc87a31d03738081
- model-request-aa3f3c73-17ee-4177-9437-ffbee89b2262.json；ID：63b69845-05b3-43a5-90aa-79593d3115ba；SHA-256：82c606b065f5003b398ceab108ef69a494486d395fd6c4ba2c9fa6cea43a464a
- model-request-aabaa121-547a-4a88-90b1-6872146e13cd.json；ID：033690e3-2147-46b5-ba73-24aa7709e169；SHA-256：394b178677bf440ce9180d80e946032a91924d1b2aeb8046f46c52a52a1e56e1
- model-request-afcf96c6-54ee-4f49-b9f6-30d2c13238ca.json；ID：757b50b0-2fad-47b9-b0be-b67ee6c46390；SHA-256：d6386a6c5a6e1376d891143ca8fe0949acc7ffa4646206fd7d2dd1b89290b9d9
- model-request-b07c7e3c-92c1-4af2-ad22-c9ef1dcb51ca.json；ID：7ff9e3f6-ba53-4d56-b37d-e1d23eb53b8c；SHA-256：0ae78910853169745cb85959c55eeef27b3146805a8f698634c05fc1515815bd
- model-request-b2dcea8b-bf32-40fb-8c3a-91436165d7a8.json；ID：41946dcc-cb6a-4262-a89a-7d335da84183；SHA-256：c827ad77d546a5b068b9359137f8adaa026e0e2032d8ae70ea3f55592226434a
- model-request-b537d97c-5884-4ec9-8119-0b507a50b2ec.json；ID：79e7eb12-9e35-4da4-80cb-dc53e068bc27；SHA-256：3de5d7a2474ce247a1916fbec1a8fac0dc71db72525b5e2156f1036d8d6cc7c8
- model-request-b7fa4789-1eb7-4119-8ceb-ca0e85a3539b.json；ID：2e69da4d-3a66-452a-b833-d325c1175f8c；SHA-256：acd9d59e68f7d060e86f9fdbdb1184a0eb6a2f6aabce528b401b4e889573be87
- model-request-b9477877-876e-4bfa-a74a-21d899efc338.json；ID：9d33dca5-0746-4150-8e96-cf2b3751097f；SHA-256：869786ab142e76ddad716a601b73c1cd5c2c5d4eb38934145262bccc9155d197
- model-request-ba042894-82b1-461f-abf1-8b0341517b0c.json；ID：004c1d7f-4626-4d10-b517-ecd129dd6785；SHA-256：23c1c14550d8c2599843b6587337b0905920139d5aa8ceb7ef1144dbd6f8565d
- model-request-bad4ad96-f20e-4a0b-bf54-fcc417bb6c3d.json；ID：b70c2cd6-e673-4496-93b5-5cf6ac30ef6f；SHA-256：317867abadcab232942be1b63ba455d4419dce50152d80f3d0ed9d5c38e56a98
- model-request-bcdac7e3-a5d4-4bed-b278-0ccbec04417d.json；ID：d9c698de-0a5f-449b-9006-d5182367a07e；SHA-256：7c462365c65a43b2b82eac79cba27a2e9165e5e1e62ffb29a790b44dd7a66aec
- model-request-c2a6b481-9a3c-4b96-b32c-0201fe413f2c.json；ID：04861c11-c0fc-4cb9-9d71-809a6bf8ee52；SHA-256：6315049ab0652160c9bd38fd6255100541f52926ba11d491df5bdaef47332706
- model-request-c2f43220-1b7e-4a37-89e8-ce25b62b1b7f.json；ID：9f565ab4-6ba4-42a1-b1de-dc77c7d74866；SHA-256：a5645dc49e01aa524627763807dba52ae8864ea38d9307e6eb3d865987aa4e2e
- model-request-c9df2d4e-0749-4edc-86f3-34991deb91ed.json；ID：9d3c26dc-9576-4f11-ae77-687a614c9005；SHA-256：8de1b2cbe25d3dd813df56d295668b7ef974b7979e2af2e0274bacd47b4c11ab
- model-request-cd3ac131-5c2e-4b68-a5d1-9c7a90299e13.json；ID：1a7d65bc-9923-4bd4-b4ff-302db1350795；SHA-256：1732e291767fe2b60b59572770d18cc2e769c66312cc4aa34ab6c7b71128a840
- model-request-cf1f16ae-c046-40d4-8d46-d3fceecd5451.json；ID：2711c47f-d8ab-492f-8a9e-3519e62d2bec；SHA-256：58c5908c747393c7b259a8857c45bac4413312e84582ee21a9f2947611c74418
- model-request-d08c292b-de59-486d-893e-18a4601c3598.json；ID：670a4b9c-4d51-4266-aa77-274b481f68f6；SHA-256：59de7b2a3282be567014dbc21da96059b209d09d5d30c9770664f4bf3f2f5225
- model-request-d0e26d0c-3f3c-4ae3-ad26-59ec39b08bc1.json；ID：a6fcd4b1-7ff0-42b1-ab94-9feae1d68d71；SHA-256：8aad1f63aadbf6ae90d9e26023ced40aa49a1d26d0fa212f5a3acabdfca38ac9
- model-request-d3500c7f-b70b-43b3-ab7f-362eeb07f24e.json；ID：d06717a0-3bac-41ac-899c-2303dbecdcb0；SHA-256：25fe47f2e42f4150a91718aad5d6b87ef9adb2fa224d25ca567e637a4ad25cd6
- model-request-d5873891-0c39-4f54-a46e-07717bf9b7aa.json；ID：5025abc4-3b40-4374-a6a6-a653021a1546；SHA-256：64931fb9cb66ebc16fc4e84a44b2b94ad83f7134132a4aaea556ca5a17cb91df
- model-request-de704f8c-6522-4683-b63a-f0e6a4cf3cb8.json；ID：8fdbe443-df51-4e71-99b0-86632c9ee970；SHA-256：5baf5e3183fb8d78a160b52609cddd59d66f1c8fe336d18273326e00d8aad887
- model-request-e9fcb9e8-fab8-43ed-af56-b8d742470823.json；ID：d21a467b-4445-430c-b940-48d0ef944555；SHA-256：36a1aa1886c5c2cb75fdc5fd9cc3ecf873f6c1c9862896412ab38215e8c64618
- model-request-eac4bd79-8a34-43a5-abc4-642c9477ad8b.json；ID：902e864a-fcb7-4226-9abd-1e8a43ee2113；SHA-256：cea856f142a698c1c325d38bba9426d6bb4f4f13250cb68e463216cf08b525f7
- model-request-ebd5b277-11ff-4365-84f2-23740ae7c24c.json；ID：e58a2f64-f2fe-4279-8ceb-aa5e128e1355；SHA-256：5ef1aa2a40c0f18525a92975c30fd57039697cedff0c22f3705a19b8bd2e26dc
- model-request-f51f54dc-45b3-41a4-8145-29c9596944dc.json；ID：076fe29a-c5cb-4a94-8ee1-100559f0ed46；SHA-256：c06c5a3cbdfc57c90da45bc800e39f863db64ad9280d8b59fad99bc2b57ff410
- model-request-fd4c6efd-a728-460f-9c2a-3e87ec213d9e.json；ID：3bf4043f-cc18-4749-ae78-f331b7dbb83a；SHA-256：9f9a27116fa47e2a5a297c2a34d025ef2ba740e7736122f4a040d783d830406a
- model-request-fd4e8dec-1180-4ecc-997b-16e02605d5e8.json；ID：de23d9f1-e6de-4f6b-86ef-ffd843272464；SHA-256：c1d28e3ee158808e824127806fb1e1cb54f07bff74c59e9477e7fb1cb7a38905
- model-request-ff56a9ef-5161-4c35-917e-824ec12bd7b6.json；ID：6a86500c-911b-4b72-964d-fdff8dc8bebd；SHA-256：cca855a92d01b8ec91aeca522b314703c7eb3fb09c267f85817aeb76ad3f60a4
- model-response-024be961-0211-490e-9f04-9b748e026dbf.json；ID：6d50d9a5-1a81-40ad-b06c-76eb6ce9dd9c；SHA-256：fdcc7370daf3e58b12aa1c2759a87e751b4ae85be21ff9971fb71ceeaf749107
- model-response-04243770-7a31-4cbd-8a41-27e41b6d08e7.json；ID：0a5f9860-89f7-447b-82a5-36b13720365a；SHA-256：c67c02ff35c54d39b18b00d9169520b651025d48a92324bcad5e547aa4229b00
- model-response-08456764-3cef-4921-9d97-2598535643d9.json；ID：593c9a59-8192-4ab5-ab7f-f55200615beb；SHA-256：dee42ba07205b83dca185d0633e5fa35059f20adcd941753c297a78576e86a9f
- model-response-0b9bae3c-a975-428b-9c42-042f6c971131.json；ID：f234e55c-d615-4093-bfff-13ffd1daf34a；SHA-256：d24edf69b71121676e4193d03d5a1b75ca7d47d7e9cf3f6dc2811037791e23a6
- model-response-0d1d5e8f-7f3d-45e9-bec4-acd45a18c384.json；ID：03917632-0007-479b-be49-85e6df17a0aa；SHA-256：e634b64777bd151005614164fb7d430e557fe99b93a48b154c926ac3207377de
- model-response-15e31caa-f6f2-4f20-82c7-9704a4999a11.json；ID：43d550a2-edee-42bc-8448-16b94a3ff76f；SHA-256：1b72bd2495cb90fe13e6aa885234782fbb0a4c6992783c1c74adad499bb3c7eb
- model-response-29e6d813-bf4d-4ab6-987b-e8ddba71729d.json；ID：d5c47342-af8c-4eb5-93b0-9feaa52369bb；SHA-256：2895bd68de7f7bfea7751f5d0fec81a0366d7c90eed75452ccb81664915c26dc
- model-response-2b5eaf3d-beb8-4aa7-a4d0-aef90a2e9234.json；ID：39da8dc0-25a8-4271-b394-d4d0babc7c67；SHA-256：eeee79268d8ce3bfb8ad2188995314939aaa610a90fa83ee2e9c472b56c88580
- model-response-2cdefd14-5165-4355-b4ce-77379ceb7a84.json；ID：a6d0e051-e78e-4fc1-82bd-e365f338f3c9；SHA-256：cd120738494f5ab02524e76d7c520ea38a85290a83b4da3a9fb8ac97699fe96f
- model-response-30c11b14-c5e7-4714-aea2-26444063096c.json；ID：5b1b9e4c-dbc6-47f2-b6f8-eb2f722ebe8e；SHA-256：18e1b9a4989949fc81ffbfbf477f5b37b490eac41d45cac0c29d465fdc9a8ca5
- model-response-325ba080-0a81-4cb4-98b1-ea7c8c51858a.json；ID：5966de3d-58c7-42a5-99cf-a4c6d294455c；SHA-256：df457902af517981634c4616e8f4ab0f4602d2bd0cc7adc551ca9b59c110613f
- model-response-36b1ca18-415c-4fcf-917c-1cef26f2fc17.json；ID：bd24ae92-984e-43ed-b17e-fc6c7fc274d7；SHA-256：71a3ef26c1c3c037b2241ba6046410601ba517bca2a5cb7ce3444e04d511af95
- model-response-3b01a2b3-8d56-424d-8eb8-b31ba2dd07a5.json；ID：b58209b4-d264-48c5-8a15-5df2b3da7547；SHA-256：d415c0c32048b8a61667d5ee957a76609512c5077a0955fab13e388886c803bc
- model-response-3f7e7bfd-d3da-4b48-bd97-f2b769159700.json；ID：664528be-63b8-47fd-959d-9fabb6845e4d；SHA-256：7fe7f4edb6236934c8f2faad3967c3111c79cf37d5191167a3193f992550374e
- model-response-41b65253-8d1c-4a31-b216-842a54673132.json；ID：be37b0f0-cc91-4eb6-9d92-587cfc54592f；SHA-256：89af4e8e15576fd534ab0767ca8c4f601792b99827e11240961f6afa89cec0c3
- model-response-44c4c444-ebaa-4533-8c3f-c587639f541a.json；ID：08752ae4-ecef-4b62-8b06-ec6ef4094f76；SHA-256：d5d6251c6ee163df3b548b0028ecab8e18b3d8e86bb60992a88012d1e87b81bb
- model-response-47591133-c812-45bb-9596-96e1cec50465.json；ID：2983196f-e30f-4d82-a8d1-5d20665bcdb6；SHA-256：e7386955a51eaa46a66f648b419c6b9b1c8ce65af3fe6384d1f0c2ae7764d508
- model-response-4cd39857-17ae-4292-9e97-c1c2557db69d.json；ID：dc265191-dc51-4d87-9c60-f7a85e567e2b；SHA-256：f7f99ae23bb2d51e9c1efae8484d632fd1675d54d13bf3c48d2e5d945c6b475a
- model-response-4cd3cd0e-89d8-4c14-adaa-618cad2a6053.json；ID：e3070633-032b-422c-9008-c33ce006874a；SHA-256：c8955380041400c059b3b4f04ae0014b7dd21515ff0830a8cf5ad4e3ea8912a1
- model-response-4e407ba7-3294-4acf-84aa-31284ffc9f9a.json；ID：944c4513-560d-49cb-88b8-6daa8d18e9f0；SHA-256：49a94af4b4557d8c997d7706d3d871ce7527badd3fdb3d67c65eb20a76ab2172
- model-response-51b73e8c-4115-464e-89aa-f4fdb9aeda42.json；ID：4c42315b-05cb-4ca3-99d4-75d7b85bc8b3；SHA-256：81a8d7b5ecfadfcdef7539b7b6924c10905e7174a0e00a3f4a1b5cc55bf46c03
- model-response-52f3bab5-a4fe-42cf-bdcf-93d356489d4c.json；ID：1630e824-9f0f-49ad-92cb-faad5f1f9ef5；SHA-256：9f30a27b5562740bd0285d702d4625b94f0c36ca5600cf45084a8afbd09bb64b
- model-response-55afc798-6e08-46fe-b6cb-830f00aef93e.json；ID：0da0221b-3089-4d84-925d-34c5ae331c63；SHA-256：79eb703b4e78e1e3de61e012a15a7afa537992ac745b3bca68df13ce133cadd5
- model-response-55d284a0-f1bb-472a-9d69-805f03f6aaf7.json；ID：b392cb0f-f91c-49e1-92a9-318d65a28ec7；SHA-256：6e918d72a3eb05ec766650c556c43712ea09f0c6f6941de0a349b332350c90bc
- model-response-564f3477-45d8-4447-9788-80e96903b582.json；ID：672e78e2-2aad-47ec-a796-761a0d811731；SHA-256：172dc59dd82e33cbd0459733da1d4d98c7e2ebe17ef9de8ab82f50752cf7bfa1
- model-response-593aa79b-de78-4776-abd3-cef3caae6726.json；ID：988e121d-e9c2-450b-a985-83bff1b5ed39；SHA-256：d6da0f411239fc4bfcbce72db06f454e505173a22473554a53bd34b077dde148
- model-response-68b974f6-28d3-4c8c-8096-afc9bd2491fb.json；ID：e7e616fb-89e3-4ace-8964-d15d8a5cc2b1；SHA-256：6f09f24674570dc7f1b10f5d174763a371dd1a59c138b075e46ba0d8fefa7b14
- model-response-6d4cd802-2483-42f4-897d-b233cb450e19.json；ID：52ca23d1-4030-4151-b3f6-d4d1f842c048；SHA-256：f1ea7386f59ce148c21d9212004c6600dc38d32b9833b462b9925b5d101d7a81
- model-response-71d38a91-53fb-4f67-88a9-b0b7a5a1f578.json；ID：1ac541ab-63f8-4f87-9b05-d37e0fa09d37；SHA-256：b1b12452b33eb738dc32353896f576b77f20f9b29caee6084ed58559f8a5e2bc
- model-response-794afeb4-d83c-4027-8dcd-fae4f4c3b500.json；ID：94cfe22b-b044-47b6-a98c-ab0e5022c5e9；SHA-256：b6d9beee3dae3afab346ee9557513af2b637ceb4d152b2e00560b9afe9196064
- model-response-794bd52d-8147-4934-b732-cf3ca8d5dd5e.json；ID：c2812e21-9475-4956-893c-2391ad8b5fb6；SHA-256：4742e6f3a6ab8114af3495e7920666d74b392d0d0a0109aa57623df8851ab1a9
- model-response-7a6f0c4f-3c48-4829-90e5-18d075816a82.json；ID：ce70ddc6-e42f-4114-8811-169e35b20957；SHA-256：597481cc0e8139b3c44bd3b50085e1c142faaf422b87da1539ea48eedb60708d
- model-response-7a92e1cf-eaad-4298-a494-cf7903cbd336.json；ID：b231c32d-a7ab-4f65-9370-cda8a1180b35；SHA-256：193ed5e407a5155d2640ded79215d588358292852805064bbb2f260e1a9110c3
- model-response-7e1ee18e-90f7-4dcc-aa97-7c8104760071.json；ID：f020484f-17ec-4858-95b9-5621740febca；SHA-256：7005b52c2beffaebc6a331f545d27fb2212f7432e042ce132322f01a8eeed91c
- model-response-8292f236-ef78-4d9d-979d-72627419b9f7.json；ID：fbbac21c-f3dc-4536-8cae-383562970749；SHA-256：c1e1db670d30692be914175573a44ae2614f1bff95baa286eec0254222d0f396
- model-response-91672deb-15c2-4d46-8f98-375ce23e7da7.json；ID：f8bbad07-0dd2-48e2-868a-c22ad1b967ca；SHA-256：f7f1f1d646de25fc1080a0a5babb27bef13bf4d1e236f670067f7f8790c82760
- model-response-9211d391-586a-4ea5-96f9-2a58b0e0ee9a.json；ID：f6c882a2-eb4d-491c-b58c-79e1b1027d94；SHA-256：178e4fb0020a28d92146d1368cc7cfb928767dba14301f2105a189c56f49f0ce
- model-response-9a2a50f5-f50f-4b92-9d05-b8bacd3ffa91.json；ID：b24abf3c-7ae5-45fd-9eb1-6df036d1db4e；SHA-256：d03ce91af335b7f0e4221caba79fff6a008c4ca1f9ce75eae17c2105d19fb854
- model-response-9c0c0657-62be-4615-886f-79063b18b94c.json；ID：f814ab90-9cc6-4c4e-a3cc-fbe2954b737b；SHA-256：0a14f1d80411829d75cdbe831b2346be5256d7f8ad3452fe655c79d76867c7a7
- model-response-9d5e5e62-dec7-416b-b02b-726ae4f5fd0d.json；ID：2fa77c3e-8b0a-4a16-9fb6-0d550539403f；SHA-256：34a590702ceb4909a1813d70132a27307187f092c2d33a78f1cf925d5249443d
- model-response-a04b9a47-31df-44f4-987a-770fd9ccd79d.json；ID：7b17f0c6-5c56-412f-b751-f3c6fbb318b1；SHA-256：7ca102eef227193880867878a12b225606b2e780c419542f6f698babd83d5580
- model-response-a193f7db-817e-42f7-979b-507bef4fa6e6.json；ID：d6c31cb4-f1a5-425b-86ee-5fd7f0c0f646；SHA-256：83b419c2bc0dc99d425c08b9f8baaf571e3a3e522b334c9fb39908835e28e753
- model-response-a9eb78a6-3b93-4261-8406-57659126a13b.json；ID：d4599d35-5f41-4d16-813f-47934f2a31fe；SHA-256：f2694c8d9674d1de3e341628379c73e719b2e627629d3d0b9cca3dcd5b6242e7
- model-response-aa46a409-6338-4b64-90a9-3c1a61f70609.json；ID：0d779cec-735e-460a-be09-5d9786880501；SHA-256：500e8fa357f6f981db35f785d8c4c8ea1bbe1ada700b5e6fc6f5fa555543d308
- model-response-ad900d35-9f91-4217-820a-00a2c92b7221.json；ID：8abef93e-7cdb-4224-947e-d3886572120a；SHA-256：3956f89cf7c560eaa999eed68d0d4f1113e29887be82821e107a4d1888988abf
- model-response-ae55e621-1035-4351-8834-56e8c95d8f0d.json；ID：2316e7a2-0030-4b0e-bf69-9bab39d4f07a；SHA-256：3b9b699f1da71d79043fb9805b1b86703dc30442bf8cfe2de578a40c6056b264
- model-response-af623b82-f780-45d4-a42d-0e6ccac8a88e.json；ID：dc81fdbd-1209-4502-81d0-7da05fa8753d；SHA-256：1c4c2b1f40c752899ea4c60e40be45826630e533a290c49715383902f4296c21
- model-response-b1d39552-be6b-4502-9413-fd5b414d2cbb.json；ID：6356a442-9287-4381-aef5-61834774b69f；SHA-256：d98a5802a7336917d85d5a28257b7e77b48a6c224526f7316578f6a90687bd81
- model-response-b1d84b9d-9601-4f31-8bd3-fce17ffd70ca.json；ID：2c4c6023-0a7e-4571-b44f-3e56d4f9dbe3；SHA-256：45d420d40bb8d27f0745e8d9a490a8dd5838f612d21c6e5c371a9451b1563209
- model-response-b5ed33ea-5ca7-4609-9edd-62d8f5eb6719.json；ID：d00580c4-b3a1-4f70-8030-de75516d759a；SHA-256：ac2fa723846844e196308d39b4392b6e4de777e5742264f2ee1ebe40cf9c38b3
- model-response-bf1ed349-24f0-4339-a47a-e0fe72d5b5fa.json；ID：f7b58bcd-1269-4a78-bfcd-cb580e469822；SHA-256：8609e03f1ad2d931833304dac38d3270d0faa7772263503b94bfcc7567e80486
- model-response-c140247b-f803-400e-8513-1c30851b8da7.json；ID：6a0c580d-bbe1-4687-bcaa-a101af9de459；SHA-256：0e0e7bdd5b61cd7f0e05bca249d146380bc5592b213c2c991c1a681a9f0e005f
- model-response-c31d2f74-d4f6-4f6b-b116-5df1959bde63.json；ID：f78b04f8-0d07-4ca0-ab2e-76e3f1e6f04b；SHA-256：180be99c5fc99e237a8d80fb9bad56f1e04412c0283ce4095f0e2cca80918b7d
- model-response-c3797e4f-61a7-4a40-af6a-15836d36c37b.json；ID：6e0d3ad3-8aa9-4684-89e9-ddb4e9776721；SHA-256：a8fa260273067aa31a8e62ef00819fd733828e22494c01c3d53e1c3255b226b6
- model-response-c7f61f6d-77b3-4972-a66d-ee4493c8ec51.json；ID：3198c234-a697-41d3-98d2-21d4dc749bdb；SHA-256：9940e38c3fd180c337033841d39e60844c215b0e3b1a6676a384a6becb5228ff
- model-response-c81370c0-2e69-4bfd-8358-313aae3b2714.json；ID：942baba9-2d58-4683-ad60-56ffc91e2091；SHA-256：a13eca236eccddce7c61a3a5a60b4264e3343d386ed7abaeefebc1d0e436fa11
- model-response-cfacc822-c3d4-4c0a-92ca-92646ea712f8.json；ID：87ca010c-63b2-4131-b99b-f4f54de0225c；SHA-256：7f6cfd75963b987acc50a384d84067ba221115d8b4c18824755a9be5e5fdf17a
- model-response-cfc2ac55-8e08-4e4e-a739-79a66716f238.json；ID：07f091f7-1ed6-45ab-9906-6790df678b3c；SHA-256：05fb4a7fc116fcdbc385aff74e0708cbde3d9f5559b12941a983e23e25dba18e
- model-response-d065ff5c-4eef-48c6-b223-1159126d2aa0.json；ID：552679ea-4881-48ce-81ee-a416ad4f7265；SHA-256：50126b01f1013538b812c581d8cd17855c59e1532b90925acaa0930dcac743e0
- model-response-d1f7eb81-b7dd-4907-8fe7-2faf8c6cc986.json；ID：60f4827e-63c9-4413-aa7e-09aca1bce0a5；SHA-256：6576c875d6b777ba8343e04dcccb97d89464bc7e16bda3336b4f9cd9a2180a53
- model-response-d38120c1-2cc9-424c-bab2-a0a5b4c682b8.json；ID：04b3e8c4-6c78-4a1b-97f4-bee2bc002004；SHA-256：78828b0349938cde77f0b9b765b485dd64160e248cf14fa50fd6604c0c419685
- model-response-d674ace1-05c4-4624-89a2-72f6bdd8989b.json；ID：8fd8b9e7-6dfd-46f3-a631-ec42aaebaed6；SHA-256：6fbeb6d8d9bbb06ec6b11d8dc6e4d8d06a00485f1e142d0dc5ecddadc1cb2e6e
- model-response-de19c75a-625a-498f-9c9a-be5f694ca6eb.json；ID：b51b0c04-b217-486f-bac1-127370296433；SHA-256：85cde5b56703822e4f3e544099fd8320b04f6e2300adec6d7f17504a6de66f9e
- model-response-e0871d99-34af-4292-a213-9c8a84930d16.json；ID：6e60b0f8-fa5c-4aa4-a843-cc68be785637；SHA-256：84e7313aff9fa01b8b4c4d433140147842dd5c20f4403e744de75b2bc1412869
- model-response-e383b90a-9edf-4cdb-bf36-6faf03729ea2.json；ID：7516d828-dc66-464f-b476-543725de68a1；SHA-256：9bec809be110b43d219ad300375a55da1176a8ed025f46b0604d4a30f9d45f06
- model-response-e71dd0cf-7fac-4fe6-85aa-1a8381318338.json；ID：5ccd26b7-b143-4bd7-92ad-e8b8db02cea4；SHA-256：0f7d9f6277f9469015b83adc464f45ccdb21290133cfe12bcd60a3a6fd641b1d
- model-response-e824407c-7074-44aa-84e7-52a212fda5fc.json；ID：646a1e33-01ba-4b3e-b0aa-a7f34eb39682；SHA-256：e3e7a3ca4284de5fe291ac87796ff1a2a6222e12b8cef5cc0d644773cb67d44f
- model-response-e9746c7b-3bb8-448c-a631-e30c1dcd1b55.json；ID：b3adef9f-062a-42a0-9999-fddf60c07c31；SHA-256：6560a13ea5823adad7298e445415b6289e6e66398728b2a82b63115274e4dd40
- model-response-f560cb9a-7180-4e6f-92d6-ac7294be003b.json；ID：15e9ae36-eac5-4ffa-896a-b1de9387613a；SHA-256：02224115b464e11b523dacf39a6db5072d04ab9fdeaa270cd808704ea6aa09c1
- model-response-f6468dc8-6908-4fcf-8d75-3aa188663d86.json；ID：9e7f40bf-0ced-4351-9cb3-815cf0640d01；SHA-256：526036e98e957741bef7357aaaf23b4df0b7d979a4fb1e6a4896ada21f6fa37f
- model-response-f8fe52e1-90de-4af9-a1cc-c47de6ca1139.json；ID：004e8622-51bf-4eb1-9ac6-70f7563060f7；SHA-256：3d42c2e3cb5b561f9d51889648392f130b6a272f3e755c518bb7e6a4cfda22f5
- model-response-fea1e56a-8d51-4a10-bd81-c5639eb2afac.json；ID：935a7b88-516a-4a06-aef0-400a79b2190c；SHA-256：a7e19db8f54ea7f41ce0c7ddeb8e7f60f233b43cafc105dec655f82fcf95e8c6
- model-response-ff50f9ab-8e85-4b41-b7ef-7bd48d56a55e.json；ID：41994b66-bc6d-4c5d-a6b3-4c3f538e095c；SHA-256：f356fdabb5a0ef491d13604276cc5f2f972e6ade860e4d0f3abb0adf68978076
- p07-ollama-images-vuln.zip；ID：a99a9203-fd91-4997-83e5-74fbe58f8dc4；SHA-256：a6c801d04e87e51d4c10d6e1bf4f00d6e811b9e61cf60a3978c6df2358da0983
- snapshot-manifest.json；ID：0c96e74a-efa9-4577-82ef-e9db88bae720；SHA-256：e111cedb6ca586ebaa5171a265d2f3f870340312d41add00de8f6cdc5e30ca7c
- source-snapshot.zip；ID：e328299a-5e73-45e3-b635-1946489bf7d1；SHA-256：f109924f0ee3ca5a80478d444ac6f0eaa250ea4acc668f1cd3a29a830ea2b4fc
