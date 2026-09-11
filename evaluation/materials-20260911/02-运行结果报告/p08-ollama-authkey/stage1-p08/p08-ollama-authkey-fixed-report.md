# AegisAudit 分析报告

项目：对照池评测 20260911-073448

任务：e34911f0-8b85-4a15-a73e-422ad41e7bc3

状态：Completed

目标 SHA-256：5cd036c891bc32e535bfbe8096e250b29ea0b7cd2b34609e9665af1620207827

结果快照 · 数据截至 2026-09-11T07:45:09.309Z · 导出时任务状态 COMPLETED。漏洞审计：COMPLETED；独立复核：COMPLETED；模糊测试：NOT\_RUN；运行验证：NOT\_RUN；利用验证：NOT\_RUN。静态复核不代表已在目标上验证漏洞或利用影响。

| 程序单元 | 文件 | 位置 / 地址 | 解析质量 |
| --- | --- | --- | --- |
| GetPublicKey | auth/auth.go | L55–L75 | PARSED |
| NewNonce | auth/auth.go | L77–L84 | PARSED |
| Sign | auth/auth.go | L86–L117 | PARSED |
| auth/auth.go | auth/auth.go | L1–L117 | PARSED |
| keyPath | auth/auth.go | L21–L53 | PARSED |

## 审计策略与优先级

这是一个单文件 Go 认证模块（auth/auth.go，5 个单元），负责定位 Ollama 私钥文件、读取/解析 SSH 私钥、生成随机 nonce 与签名。审计优先级按“外部可控输入 → 信任边界 → 关键逻辑”排序：重点评估调用方传入的 length/reader 是否会触发内存或索引异常，以及私钥路径解析与文件读取的信任边界和部署平台一致性。计划器只做优先级排序，不在此处下结论；全部 5 个单元都会在预算内被审计。

1. u\_7ffe413d0d211c8b61ecd260628efdac：NewNonce\(r io.Reader, length int\) 直接以调用方传入的 length 执行 make\(\[\]byte, length\)：负值会 panic、超大值会造成无界分配/DoS，属“内存或索引操作”语义风险，需核查所有调用点是否对 length 做范围校验。
2. u\_38f735b7ce0c1f3963c6cc75d40bf891：模块级上下文：导入 crypto/rand、ssh、os、path/filepath，定义 defaultPrivateKey 常量。需审视整体信任边界（本地私钥文件、环境变量/家目录）与跨函数共享假设，并确认这是否为唯一认证入口。
3. u\_28eca38339be92da9df49f8c728e339c：keyPath\(\) 承担路径边界：硬编码 /usr/share/ollama 路径、filepath.Join 拼家目录、fileIsReadable 先 Stat 再 Open（存在 TOCTOU）；返回前未再验证可读性即回落家目录路径。需检查路径可控性与错误回退是否让后续读取落到非预期文件。
4. u\_4cbd963ab51c754b1a1d9765346eaf9c：GetPublicKey\(\) 读取并解析私钥文件，错误经 slog.Info 记录（含 fmt.Sprintf 错误详情，注意敏感信息/路径泄露）；返回值经 TrimSpace。需核查文件读取的信任边界与错误信息暴露。
5. u\_24db6dafbb1671305934efdaac4bc206：Sign\(\) 读取私钥、bytes.Split 解析公钥并取 parts\[1\]、拼接 &#39;&lt;pubkey&gt;:&lt;signature&gt;&#39; 返回给调用方。需核查索引访问（parts\[1\]）、签名数据来源 bts 的信任边界以及返回值格式是否被下游安全使用。

规划限制：call\_graph\_complete=false，未提供调用方，无法确认 NewNonce 的 length、Sign 的 bts、GetPublicKey 的调用来源与输入是否外部可控；相应风险只能作为待验证假设。

规划限制：target platform 声明为 windows-x64，但代码使用 POSIX 固定路径 /usr/share/ollama；实际部署形态未知，路径回落行为无法静态确证。

规划限制：未识别到构建系统、入口、输入接口与依赖清单（metadata.missing），无法执行或动态验证，所有判断均为静态语义分析。

规划限制：Semgrep 状态为 UNSUPPORTED（Windows 原生执行器缺失），只使用内建线索；lexical clues 仅为线索而非漏洞证据。

规划限制：verification 与 vulnerability\_audit 均为 NOT\_RUN，未记录任何混淆/解包转换，不声称存在此类处理。

规划限制：human\_annotations 为空，无可交叉验证的外部参考。

## 发现与复核

静态结论范围：COMPONENT

### NewNonce 未校验调用方传入的 length，负数或超大值可导致 panic 或内存耗尽（DoS）

CWE-789 · MEDIUM · 复核 VALIDATED · 验证 NOT\_RUN

输入：NewNonce 的第一个/第二个形参 r io.Reader 与 length int，均来自该包的调用方（本快照内未出现调用点，属于未知上游，可能为请求参数或长度字段）

危险操作：make\(\[\]byte, length\) 按未经校验的 length 直接分配切片

防护缺口：缺少 length 的取值校验（例如 length &lt;= 0 或 length &gt; 合理上限时返回错误），也缺少上限常量或配置约束

前提：调用方能够影响 length 且可传入负数或极大值（例如由请求体/配置/外部输入推导的长度）。若所有调用点都传入编译期常量，则该风险不可达。

影响：负数 length 触发运行时 panic（makeslice: len out of range），在服务端表现为请求处理崩溃/进程级 DoS；极大 length 造成巨额内存分配，引发 OOM 或内存压力导致的整体不可用。注意 io.ReadFull 在正常正向长度下会正确读满或报错，不会越界写入，因此影响限于拒绝服务。

修复：在分配前校验 length：若 length &lt;= 0 或 length &gt; 预设上限（如 64/128）则返回错误；对 nonce 长度使用包内固定常量而非外部参数；如确需动态长度，改用 io.LimitReader 并配合上限校验，同时由调用方对参数来源做白名单/范围约束。

- 证据：auth/auth.go L78–78 ；产物 f31f8c3b-4570-4896-8a62-4df395c798a2；引用：	nonce := make\(\[\]byte, length\)
- 证据：auth/auth.go L79–81 ；产物 f31f8c3b-4570-4896-8a62-4df395c798a2；引用：	if \_, err := io.ReadFull\(r, nonce\); err \!= nil { 		return &quot;&quot;, err 	}

复核 v2（MODEL，VALIDATED）：在组件接口层面复核：NewNonce 的形参 length（第 77 行）未经任何处理即作为第 78 行 make\(\[\]byte, length\) 的长度实参。函数体（77-84 行）内不存在对 length 的下界或上界校验，也没有上限常量。Go 语言语义下，make 传入负长度会抛出运行时 panic（makeslice: len out of range），传入极大值会触发巨额分配或分配失败 panic/内存耗尽，因此该形参到分配操作构成未受控的分配尺寸（CWE-789）与可用性影响。io.ReadFull 只保证读满或返回错误、base64 只对已分配切片编码，均不能约束分配尺寸，故不构成反证。参数本身即组件输入边界，无需上游调用点即可成立该组件级静态缺陷。

反证：io.ReadFull 在正向长度下正确读满或报错，不会越界写入；base64.RawURLEncoding 对已分配切片操作安全。这些只是限定了影响范围（非内存越界/泄露），并未对 length 施加任何检查，因此不能反驳未受控分配这一论断。函数内也不存在任何隐含的尺寸约束或类型层面的下界。

待补信息：快照内不存在 NewNonce 的调用点，无法确认部署中各调用方传入的 length 是否为编译期常量，还是由请求/配置等不可信来源推导；也无法确认上层是否 recover panic 从而把影响限制在单次请求而非进程级。这些属于部署层条件，不改变组件接口层的静态结论。
静态结论范围：COMPONENT

### keyPath 回退分支返回未经文件类型/链接校验的私钥路径（符号链接跟随与 TOCTOU）

CWE-59 · LOW · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：环境变量 HOME（os.UserHomeDir\(\)，第47行）与本地文件系统状态（/usr/share/ollama/.ollama 是否可读、$HOME/.ollama/id\_ed25519 的内容/类型）

危险操作：return filepath.Join\(home, &quot;.ollama&quot;, defaultPrivateKey\), nil —— 直接返回私钥路径（U0002 第52行），随后被调用方 os.ReadFile 读取并交给 ssh.ParsePrivateKey（U0003 第61行、U0005 第92行）

防护缺口：回退分支完全没有复用 fileIsReadable/FileMode.IsRegular 校验，也没有 Lstat 拒绝符号链接、未检查文件属主与 0600 权限、未使用 O\_NOFOLLOW 在同一句柄上读取；系统路径分支同样是先 Stat 再 Open，与后续调用方的 os.ReadFile 之间存在 TOCTOU 窗口

前提：系统路径 /usr/share/ollama/.ollama/id\_ed25519 不存在或不可读（第43行返回 false），且攻击者对 $HOME/.ollama 目录有写权限，可创建 id\_ed25519 文件或指向其自有密钥的符号链接；未验证部署是否满足该权限条件

影响：服务会以攻击者提供的私钥作为自身身份生成签名并导出公钥（Sign/GetPublicKey），导致身份冒充、签名伪造或把错误身份绑定到服务账户，破坏基于该密钥的认证边界

修复：回退前先用 os.Lstat 拒绝非普通文件与符号链接，校验属主与权限位；读取时使用 os.OpenFile\(..., O\_RDONLY\|O\_NOFOLLOW\) 并直接 ReadAll，去掉 Stat→Open→再 ReadFile 的二次打开；或在部署中显式固定/配置密钥路径并限制其目录权限

- 证据：auth/auth.go L52–52 ；产物 f31f8c3b-4570-4896-8a62-4df395c798a2；引用：	return filepath.Join\(home, &quot;.ollama&quot;, defaultPrivateKey\), nil
- 证据：auth/auth.go L42–45 ；产物 f31f8c3b-4570-4896-8a62-4df395c798a2；引用：	systemPath := filepath.Join\(&quot;/usr/share/ollama/.ollama&quot;, defaultPrivateKey\) 	if fileIsReadable\(systemPath\) { 		return systemPath, nil 	}
- 证据：auth/auth.go L47–50 ；产物 f31f8c3b-4570-4896-8a62-4df395c798a2；引用：	home, err := os.UserHomeDir\(\) 	if err \!= nil { 		return &quot;&quot;, err 	}
- 证据：auth/auth.go L61–61 ；产物 f31f8c3b-4570-4896-8a62-4df395c798a2；引用：	privateKeyFile, err := os.ReadFile\(keyPath\)

复核 v2（MODEL，INCONCLUSIVE）：keyPath 是纯路径选择辅助函数：systemPath 分支经 fileIsReadable 校验（Stat+IsRegular+Open 可读性），回退分支仅用 os.UserHomeDir\(\) 与编译期常量 defaultPrivateKey 拼接。函数无参数，返回路径中不含任何调用者可提供的路径片段，因此不存在参数驱动的路径穿越输入；该断言不构成该边界上的 INPUT\_CONTROL 缺陷。回退分支确实没有复用 IsRegular 检查、没有 Lstat/O\_NOFOLLOW，这一点属实，但要把它变成可利用的符号链接替换或凭据替换，必须有额外攻击者能力（对 $HOME/.ollama 目录的本地写权限、或控制进程 HOME 环境、或构造符号链接），代码与证据中均未体现该前提；这不是本组件参数边界可证明的输入控制。TOCTOU 子断言（Stat→Open 与后续 os.ReadFile 之间的窗口）缺少共享可变资源与并发攻击者影响的证据，单独的分次 resolve/check/open 不构成竞态证明。故在缺少该额外前提证据时不能判定为已验证缺陷，也不足以直接否定（缺少部署权限/属主与 HOME 来源信息）。

反证：回退分支无 Lstat/O\_NOFOLLOW、无属主/0600 权限校验；调用方 U0003 直接 os.ReadFile 后 ssh.ParsePrivateKey，未再加校验。

待补信息：部署中服务以何身份运行、HOME 来源是否攻击者可控、$HOME/.ollama 目录属主与权限、系统路径 /usr/share/ollama/.ollama 是否存在的实际部署状态、是否存在并发写者。
静态结论范围：COMPONENT

### 私钥文件读取仅依赖固定路径与可读性检查，缺少所有权/符号链接与 TOCTOU 防护

CWE-367 · LOW · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：进程运行身份（os.UserHomeDir 结果）与本地文件系统状态，而非请求级外部输入

危险操作：os.ReadFile\(keyPath\) 读取 SSH 私钥文件内容（auth/auth.go:61）

防护缺口：keyPath\(\) 仅在检查阶段用 os.Stat + Mode\(\).IsRegular\(\) + os.Open 判断“可读”，未校验文件所有者/权限位（如 0600）、未使用 os.Lstat 拒绝符号链接，也未做打开后再 fstat 的原子校验（O\_NOFOLLOW / 单次打开句柄），随后在另一函数中用路径字符串重新打开，存在检查与使用之间的时间窗口。

前提：攻击者已能在 /usr/share/ollama/.ollama/ 或当前用户 $HOME/.ollama/ 内创建/替换 id\_ed25519（或其符号链接），且进程以更高权限运行或该目录属主可写。

影响：进程可能读取到攻击者指定的私钥文件并据此生成/签名身份数据，导致身份冒充或签名归属错误；读取内容不会回显给调用者（仅返回公钥），但私钥材料会被载入进程内存。

修复：对私钥路径使用 os.Lstat 拒绝非常规文件与符号链接，校验 owner/权限位（非 0600 或非预期属主则拒绝），并在同一打开的文件句柄上用 fstat 复核后直接从该句柄读取，消除检查-使用时间差；可考虑在配置中显式指定密钥路径。

- 证据：auth/auth.go L61–61 ；产物 f31f8c3b-4570-4896-8a62-4df395c798a2；引用：	privateKeyFile, err := os.ReadFile\(keyPath\)
- 证据：auth/auth.go L22–40 ；产物 f31f8c3b-4570-4896-8a62-4df395c798a2；引用：	fileIsReadable := func\(fp string\) bool { 		info, err := os.Stat\(fp\) 		if err \!= nil { 			return false 		}  		// Check that it&#39;s a regular file, not a directory or other file type 		if \!info.Mode\(\).IsRegular\(\) { 			return false 		}  		// Try to open it to check readability 		file, err := os.Open\(fp\) 		if err \!= nil { 			return false 		} 		file.Close\(\) 		return true 	}
- 证据：auth/auth.go L42–52 ；产物 f31f8c3b-4570-4896-8a62-4df395c798a2；引用：	systemPath := filepath.Join\(&quot;/usr/share/ollama/.ollama&quot;, defaultPrivateKey\) 	if fileIsReadable\(systemPath\) { 		return systemPath, nil 	}  	home, err := os.UserHomeDir\(\) 	if err \!= nil { 		return &quot;&quot;, err 	}  	return filepath.Join\(home, &quot;.ollama&quot;, defaultPrivateKey\), nil

复核 v2（MODEL，INCONCLUSIVE）：U0003 的 GetPublicKey 无任何入参，读取路径完全来自 U0002 的 keyPath\(\)：常量 defaultPrivateKey（&quot;id\_ed25519&quot;，U0001:19）拼接硬编码的 /usr/share/ollama/.ollama 或 $HOME/.ollama，任何组件输入都无法影响 os.ReadFile 的操作对象，因此不存在请求级“路径遍历”原语。候选的真实机制是本地 check-then-reopen（U0002:22-38 先用 os.Stat/Open 检查，U0003:61 再按路径字符串重新打开）被符号链接/文件替换绕过，但该机制成立的前提是攻击者已能在密钥目录内创建/替换文件或符号链接——这是源代码之外、未获证据的额外攻击者能力，故不能据此判定为已证实的组件缺陷。即便成立，U0003:72 只返回公钥，私钥内容不会回显给调用者，影响仅为载入攻击者选定的密钥材料。

反证：路径集合被 keyPath\(\) 限定为两个固定路径；fileIsReadable 用 os.Stat + Mode\(\).IsRegular\(\) 拒绝目录等非常规文件（U0002:23-31）；读取失败会记录并返回错误（U0003:62-64）；返回值仅为 MarshalAuthorizedKey 的公钥（U0003:72），不回显文件内容。

待补信息：攻击者是否拥有对 /usr/share/ollama/.ollama 或 $HOME/.ollama 的写权限/能否放置符号链接（部署与文件系统属主/权限未知）；是否是并发替换场景（无共享可变资源与竞态的实证）。
静态结论范围：COMPONENT

### Sign 对调用方提供的原始字节直接签名，ctx 完全未使用，缺少 context/会话绑定与签名用途分离

UNKNOWN · MEDIUM · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：函数形参 bts \[\]byte（以及未使用的 ctx context.Context），由调用方决定内容

危险操作：privateKey.Sign\(rand.Reader, bts\)（第 110 行）对调用方字节流做 SSH 私钥签名，并在第 116 行以 &quot;&lt;pubkey&gt;:&lt;sig&gt;&quot; 形式返回

防护缺口：没有在签名前校验 bts 是否来自 NewNonce 生成的新鲜 nonce、没有把 ctx（会话/请求/有效期）纳入被签名数据、没有用途域分隔（domain separation）或防重放校验

前提：存在某个调用方（未在本快照中提供）将外部可控或可重放的数据作为 bts 传入 Sign；验证方仅检查签名有效性而不校验 nonce 新鲜度

影响：可被重放或跨用途复用的有效签名；若上游把攻击者提供的字节交给 Sign，则攻击者获得由节点身份私钥背书的任意消息签名，破坏认证信任边界

修复：将 ctx 中的会话/请求标识、用途标签、时间戳与 nonce 一起纳入被签名负载；在 Sign 内部或调用方强制校验 nonce 由 NewNonce 生成且未被使用过；避免把 Sign 暴露为对任意字节签名的通用预言机

- 证据：auth/auth.go L110–110 ；产物 f31f8c3b-4570-4896-8a62-4df395c798a2；引用：	signedData, err := privateKey.Sign\(rand.Reader, bts\)
- 证据：auth/auth.go L86–86 ；产物 f31f8c3b-4570-4896-8a62-4df395c798a2；引用：func Sign\(ctx context.Context, bts \[\]byte\) \(string, error\) {
- 证据：auth/auth.go L116–116 ；产物 f31f8c3b-4570-4896-8a62-4df395c798a2；引用：	return fmt.Sprintf\(&quot;%s:%s&quot;, bytes.TrimSpace\(parts\[1\]\), base64.StdEncoding.EncodeToString\(signedData.Blob\)\), nil

复核 v2（MODEL，INCONCLUSIVE）：Sign 是一个无状态签名助手：它从磁盘读取节点私钥（U0005:92-101），把调用方形参 bts 原样交给 privateKey.Sign（U0005:110），并以 &quot;&lt;pubkey&gt;:&lt;sig&gt;&quot; 返回（U0005:116）。因此「调用方字节最终到达签名原语」在本组件边界内成立（INPUT\_CONTROL/REACHABILITY 均为 SUPPORTED）。但候选主张的危害——攻击者获得由节点身份背书的任意消息签名、进而重放或跨用途复用——依赖两个本快照中不存在的外部条件：\(1\) 某个上游调用方把外部可控/可重放字节填入 bts；\(2\) 验证方只校验签名有效性而不校验 nonce 新鲜度/用途。快照仅一个文件、4 个函数（inspect\_target 显示 call\_graph\_complete=false，无入口/调用方），无法确认任一条件。同时候选的 missing\_guard 实质是把「nonce 必须来自 NewNonce 且未被使用」「用途域分隔」等新鲜性/域分隔策略放在一个无状态、不持有 nonce 存储的签名函数内部强制，这更像协议层/验证方职责与纵深防御建议，而非本组件内部可判定的授权缺陷；ctx 被声明而未使用是真实代码事实，但单独不足以证明越权或重放。按 COMPONENT 规则，未证实的额外攻击面（上游可控输入 + 验证方不校验新鲜度）属 UNKNOWN，故既不能判 VALIDATED，也不存在反驳该攻击的源码防护可据以判 REJECTED。

反证：Sign 内部未发现任何 freshness/域分隔/会话绑定检查：ctx 参数（U0005:86）在函数体内完全未被使用；无 nonce 使用记录或状态存储；返回值中不含 ctx/用途/时间戳（U0005:116）。NewNonce（U0004:77-84）确实存在，但 Sign 与 NewNonce 之间没有任何可验证的调用或绑定关系。keyPath（U0002:42-52）仅选择私钥路径，不引入额外校验，也不构成对重放的防护。

待补信息：1\) 调用 Sign 的上游代码（调用图不完整，call\_graph\_complete=false，无入口/路由信息），无法确认 bts 是否可由攻击者控制或来自可重放来源；2\) 验证方是否校验 nonce 新鲜度/签名用途；3\) 部署中该签名是否仅用于单一握手用途。这些条件满足与否决定该主张是否成立，当前均未知。
静态结论范围：COMPONENT

### Sign 重新定位并读取私钥文件缺少路径/句柄校验，keyPath 探测与 os.ReadFile 之间存在 TOCTOU 与符号链接跟随

CWE-367 · LOW · 复核 INCONCLUSIVE · 验证 NOT\_RUN

输入：keyPath\(\) 返回的路径（系统路径 &quot;/usr/share/ollama/.ollama&quot; 或 os.UserHomeDir\(\) 下的 &quot;.ollama/id\_ed25519&quot;），间接受环境（HOME）与本地文件系统状态影响

危险操作：os.ReadFile\(keyPath\)（第 92 行）读取私钥文件内容，随后 ssh.ParsePrivateKey 解析

防护缺口：缺少打开后校验（fstat 比对 stat 结果、O\_NOFOLLOW、检查文件属主与权限位），读文件与可读性探测未使用同一文件句柄

前提：攻击者对 ~/.ollama 或 /usr/share/ollama/.ollama 目录（或其父目录）具有写权限，可在探测与读取之间替换文件或植入符号链接

影响：Sign 可能加载攻击者提供的私钥并对返回的 &quot;&lt;pubkey&gt;:&lt;sig&gt;&quot; 使用该密钥，导致节点以错误身份签名；GetPublicKey 亦会泄露被替换的公钥

修复：用同一 fd 完成 stat/open/read（先 os.Open 再基于 fd 校验并 io.ReadAll），启用 O\_NOFOLLOW，校验属主 uid 与权限位（如 0600）

- 证据：auth/auth.go L92–92 ；产物 f31f8c3b-4570-4896-8a62-4df395c798a2；引用：	privateKeyFile, err := os.ReadFile\(keyPath\)
- 证据：auth/auth.go L87–87 ；产物 f31f8c3b-4570-4896-8a62-4df395c798a2；引用：	keyPath, err := keyPath\(\)

复核 v2（MODEL，INCONCLUSIVE）：Sign\(U0005\)在第87行调用 keyPath\(\) 得到路径，第92行用 os.ReadFile 读取该路径；keyPath\(\)\(U0001:21-53\)先用 os.Stat + os.Open 做可读性探测，再在 Sign 中以独立调用 os.ReadFile 重新打开同一路径。两次访问之间确实存在窗口，且 os.Stat/os.ReadFile 默认跟随符号链接，缺少 O\_NOFOLLOW、基于 fd 的 fstat 比对及属主/权限校验。但路径并非由 Sign 的函数参数决定：它由固定常量 &#39;/usr/share/ollama/.ollama&#39; 与 os.UserHomeDir\(\) 拼接而成（U0001:42-52），不存在调用方可控的路径拼接，故不构成经典目录穿越。要把该窗口变为可利用缺陷，攻击者必须已有的额外能力：对 /usr/share/ollama/.ollama 或 $HOME/.ollama 目录（或其父目录）具有写权限，并能在检查与读取之间替换文件或植入符号链接；此前提在给定证据中完全未证明。而且一旦攻击者拥有该目录写权限，直接替换私钥即可获得候选所声称的同一影响（以攻击者密钥签名、GetPublicKey 泄露被替换公钥），TOCTOU/符号链接细节不带来额外能力，更接近纵深防御建议而非新漏洞。&#39;resolve/check/open 分离本身不证明竞态前提&#39;，因此不能仅凭两个独立调用支持该 TOCTOU 结论。

反证：keyPath 的 fileIsReadable\(U0001:22-40\)已检查目标为常规文件\(Mode\(\).IsRegular\)并尝试 os.Open 打开以确认可读性；路径由固定常量与 home 拼接，无外部可控路径输入，故排除目录穿越。这两点限制了&#39;攻击者通过参数控制路径&#39;的读法，但仍不能排除候选所述的目录写权限/符号链接前提。

待补信息：\(1\) 部署目录 /usr/share/ollama/.ollama 与 $HOME/.ollama 的属主/权限位，及进程运行用户是否与攻击者同权限；\(2\) 是否存在对 keyPath 所得目录具有写权限、可在 stat/open 与 ReadFile 之间替换文件或植入符号链接的本地攻击者；\(3\) HOME 环境变量是否可被非受信方影响。这些决定额外前提是否成立；缺失时无法将该本地组件缺陷升级为可证实漏洞。

## 关键逻辑与人工修订

- u\_24db6dafbb1671305934efdaac4bc206 · CRYPTOGRAPHY · v1（MODEL）：Sign 使用 ssh 解析出的私钥对调用方传入的 bts 做非对称签名：privateKey.Sign\(rand.Reader, bts\)，随后以 base64 输出 &lt;pubkey&gt;:&lt;signature&gt;。密钥来源为本地私钥文件（keyPath 解析），随机源为标准库 crypto/rand，未使用应用自带弱随机。此处仅作密码学逻辑标注，不构成漏洞；密钥文件路径的信任边界与访问控制在 U0002 的任务中评估。
  - 原文：auth/auth.go L110-L110；	signedData, err := privateKey.Sign\(rand.Reader, bts\)
- u\_28eca38339be92da9df49f8c728e339c · AUTHENTICATION · v1（MODEL）：该单元不执行认证校验，但决定后续认证凭据（SSH 私钥文件）的解析路径，是身份令牌来源的选择逻辑：系统路径优先、否则退回家目录，返回值直接喂给 os.ReadFile + ssh.ParsePrivateKey。属于需独立标注的凭据定位逻辑，本身未做完整性/属主校验。
  - 原文：auth/auth.go L42-L44；	systemPath := filepath.Join\(&quot;/usr/share/ollama/.ollama&quot;, defaultPrivateKey\) 	if fileIsReadable\(systemPath\) { 		return systemPath, nil
  - 原文：auth/auth.go L52-L52；	return filepath.Join\(home, &quot;.ollama&quot;, defaultPrivateKey\), nil
- u\_38f735b7ce0c1f3963c6cc75d40bf891 · AUTHENTICATION · v1（MODEL）：Sign/GetPublicKey 依据 keyPath\(\) 定位固定私钥文件（第 42、52 行构造 /usr/share/ollama/.ollama/id\_ed25519 或 $HOME/.ollama/id\_ed25519）并签名调用方提供的字节（第 86、110 行），其产物作为身份凭据的一部分使用；密钥路径为硬编码相对家目录拼接，无外部输入参与，需确认部署平台与文件权限假设是否成立。以此标注身份凭据相关逻辑，非漏洞结论。
  - 原文：auth/auth.go L110-L110；	signedData, err := privateKey.Sign\(rand.Reader, bts\)
  - 原文：auth/auth.go L42-L52；	systemPath := filepath.Join\(&quot;/usr/share/ollama/.ollama&quot;, defaultPrivateKey\) 	if fileIsReadable\(systemPath\) { 		return systemPath, nil 	}  	home, err := os.UserHomeDir\(\) 	if err \!= nil { 		return &quot;&quot;, err 	}  	return filepath.Join\(home, &quot;.ollama&quot;, defaultPrivateKey\), nil
- u\_38f735b7ce0c1f3963c6cc75d40bf891 · CRYPTOGRAPHY · v1（MODEL）：模块单元中的签名逻辑使用 SSH 私钥进行非对称签名：第 98 行 ssh.ParsePrivateKey 解析私钥，第 110 行 privateKey.Sign\(rand.Reader, bts\) 以 crypto/rand 作为随机源生成签名，第 116 行以 base64 拼接 pubkey:signature。属于认证/签名关键逻辑，需独立复核密钥加载与签名输出的信任边界（本任务范围内不作漏洞判定）。
  - 原文：auth/auth.go L110-L110；	signedData, err := privateKey.Sign\(rand.Reader, bts\)
  - 原文：auth/auth.go L98-L98；	privateKey, err := ssh.ParsePrivateKey\(privateKeyFile\)
- u\_4cbd963ab51c754b1a1d9765346eaf9c · AUTHENTICATION · v1（MODEL）：该单元导出的公钥身份（ssh.MarshalAuthorizedKey 结果）与同文件 Sign 中生成的 &quot;&lt;pubkey&gt;:&lt;signature&gt;&quot; 结构相对应，说明本模块以本地私钥签名、以公钥作为身份标识；此处只做身份材料导出与私钥解析，签名校验/身份验证逻辑不在本单元内，属于认证信任边界的上游环节。
  - 原文：auth/auth.go L72-L74；	publicKey := ssh.MarshalAuthorizedKey\(privateKey.PublicKey\(\)\)  	return strings.TrimSpace\(string\(publicKey\)\), nil
  - 原文：auth/auth.go L115-L116；	// signature is &lt;pubkey&gt;:&lt;signature&gt; 	return fmt.Sprintf\(&quot;%s:%s&quot;, bytes.TrimSpace\(parts\[1\]\), base64.StdEncoding.EncodeToString\(signedData.Blob\)\), nil
- u\_4cbd963ab51c754b1a1d9765346eaf9c · CRYPTOGRAPHY · v1（MODEL）：GetPublicKey 读取本地私钥文件并用 ssh.ParsePrivateKey 解析，再导出授权公钥（MarshalAuthorizedKey）。涉及非对称密钥解析与公钥导出，属密码学逻辑标注；私钥文件路径/权限边界在 U0002 任务中评估。
  - 原文：auth/auth.go L67-L67；	privateKey, err := ssh.ParsePrivateKey\(privateKeyFile\)
- u\_7ffe413d0d211c8b61ecd260628efdac · CRYPTOGRAPHY · v1（MODEL）：nonce 的随机性完全取决于调用方传入的 io.Reader r：第 79 行用 io.ReadFull\(r, nonce\) 从该 reader 读取随机字节，函数自身不引用 crypto/rand，也没有对 r 是否具备密码学强度做任何检查或默认回退。若上游传入确定性阅读器（如固定字节或 math/rand 派生流），nonce 将可预测；该点需结合调用方确认，故仅作标注而非漏洞结论。
  - 原文：auth/auth.go L79-L79；	if \_, err := io.ReadFull\(r, nonce\); err \!= nil {

## 覆盖与错误

```json
{
  "audit_config": {
    "max_model_calls": 240,
    "max_output_tokens": 0,
    "max_tool_rounds": 8,
    "max_units": 20,
    "model_timeout_seconds": 900,
    "reasoning_effort": "high",
    "timeout_seconds": 1800
  },
  "audit_narrative": {
    "limitations": [
      "全部 5 条发现的 verification_status 均为 NOT_RUN，未经运行时验证，结论仅为静态推断。",
      "dynamic_execution=NOT_RUN 且 static_review_only=true：无法观察实际内存分配、文件系统竞态或签名调用路径行为。",
      "TOCTOU、符号链接跟随等问题的可利用性依赖具体部署（密钥路径是否可达、目录权限、是否预置符号链接），当前上下文未提供部署信息，无法判定实际影响。",
      "除 NewNonce（MEMORY_BOUNDS）标为 VALIDATED 外，其余 4 条 review_status=INCONCLUSIVE，属于假设，尚不能确认为真实漏洞。",
      "未提供人工批注，也无运行时证据、日志或调用方来源约束信息；调用方是否对外部可控输入做白名单/范围约束仍为未知缺口。",
      "覆盖为单元级别（5/5），并不等同于对每一执行路径、动态分派与未知部署场景的完整覆盖；缺失调用与动态分派仍需显式保留为缺口。"
    ],
    "recommendations": [
      "对唯一经静态验证的内存边界问题（NewNonce 未校验 length）优先修复：在分配前校验 length 范围（拒绝 <=0 或超过固定上限），并对 nonce 长度使用包内固定常量而非外部可控参数。",
      "对 3 条路径遍历类假设，采用“同一文件句柄完成校验与读取”的模式：以 os.OpenFile(..., O_RDONLY|O_NOFOLLOW) 打开后，基于 fd 做 fstat 复核（文件类型、属主 uid、权限位如 0600），再直接 ReadAll，消除 Stat→Open→ReadFile 之间的 TOCTOU 与符号链接跟随。",
      "对 Sign 的授权假设：将 ctx 中的会话/请求标识、用途标签与时间戳一并纳入被签名负载，并在内部或调用方强制校验 nonce 来源与一次性使用，避免将 Sign 暴露为对任意字节签名的通用预言机。",
      "在部署层面显式固定或配置私钥路径并收紧其目录权限，作为路径遍历/链接类问题的缓解措施。",
      "鉴于 verification_status 均为 NOT_RUN，建议在具备可运行环境后，对上述假设（尤其是 TOCTOU 与符号链接跟随）设计运行时验证用例，以确认可达性并推动 review_status 更新。"
    ],
    "summary": "本次审计为纯静态审计（static_review_only=true），未运行任何动态执行（dynamic_execution=NOT_RUN）。覆盖范围：共 5 个单元，已审计 5 个单元，无结构告警，未提供人工批注（human_annotations 为空且与快照代码一致）。共保留 5 条候选发现，涉及 3 类安全问题：\n\n1) 内存边界/DoS（MEMORY_BOUNDS，1 条，review_status=VALIDATED）：NewNonce 未对调用方传入的 length 做校验，负数或超大值可能触发 panic 或内存耗尽。这是本轮唯一被标记为静态验证通过的条目。\n\n2) 路径遍历/符号链接与 TOCTOU（PATH_TRAVERSAL，3 条，均 review_status=INCONCLUSIVE）：分别覆盖 keyPath 回退分支返回未做文件类型/链接校验的私钥路径、私钥文件读取缺少所有权/符号链接/TOCTOU 防护、以及 Sign 在 keyPath 探测与 os.ReadFile 之间存在的路径/句柄校验缺失。\n\n3) 授权/信任边界（AUTHORIZATION，1 条，review_status=INCONCLUSIVE）：Sign 对调用方提供的原始字节直接签名、ctx 完全未使用，缺少会话绑定与签名用途分离，可能被当作通用签名预言机。\n\n重要说明：所有 5 条发现的 verification_status 均为 NOT_RUN，即均未经历运行时验证；除第 1 条外，其余 4 条 review_status=INCONCLUSIVE，属于基于静态证据的假设，尚未确证可达性与实际影响。本条摘要仅复述已保存的证据，不新增或升级任何发现。"
  },
  "audited_unit_count": 5,
  "edge_count": 35,
  "eligible_unit_count": 5,
  "exclusions": [],
  "files": [
    {
      "language": "go",
      "path": "auth/auth.go",
      "reason": "",
      "status": "PARSED",
      "unit_count": 5
    }
  ],
  "finding_count": 5,
  "function_count": 4,
  "fuzzing": "NOT_RUN",
  "incomplete_agent_tasks": 0,
  "independent_review": "COMPLETED",
  "metadata": {
    "analysis_scope": "STRUCTURE_ANALYSIS",
    "call_graph_complete": false,
    "code_file_count": 1,
    "function_count": 4,
    "module_count": 1,
    "semgrep": {
      "reason": "执行器未准备 Windows 原生 Semgrep 1.176.1；使用内建线索并进行独立语义审计",
      "status": "UNSUPPORTED"
    },
    "target_sha256": "5cd036c891bc32e535bfbe8096e250b29ea0b7cd2b34609e9665af1620207827",
    "verification": "NOT_RUN",
    "vulnerability_audit": "NOT_RUN"
  },
  "model_usage": {
    "calls": 59,
    "cost_cny": null,
    "measured_tokens": 244895,
    "unknown_usage_calls": 0
  },
  "result_artifact_id": "f31f8c3b-4570-4896-8a62-4df395c798a2",
  "reviewed_finding_count": 5,
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
      "finished_at": "2026-09-11T07:38:45.395Z",
      "log_artifact_id": "",
      "name": "tree-sitter",
      "started_at": "2026-09-11T07:38:45.394Z",
      "terminated": false,
      "version": "0.25 (grammars pinned in Cargo.lock)"
    }
  ],
  "unit_count": 5,
  "unresolved_calls": 33,
  "verification": "NOT_RUN",
  "vulnerability_audit": "COMPLETED",
  "warnings": []
}
```

任务错误：

## 证据产物

- aegis-report-e34911f0-8b85-4a15-a73e-422ad41e7bc3.html；ID：ff783264-8760-4a43-9dd4-1f944022aa89；SHA-256：e600166c89c468c8c1e39067649657aeaad6204bd51fae37b5b10c1efd97433f
- aegis-report-e34911f0-8b85-4a15-a73e-422ad41e7bc3.json；ID：7c8de113-81d6-461d-a46d-6550028c3f63；SHA-256：7be42358ccae7fb5bf0eca21bf845737fc94e67655679880a03677e0dcd94708
- agent-AUDITOR-10e829b3-d7fd-4fcd-8c0a-d67b7669365c.json；ID：d5e42e7c-f49e-4007-bb11-6041c83919df；SHA-256：3d6d5b9baa6962f16fde0deb8d92d70a8d3e443cc72fd26d35e510d11f63dc7f
- agent-AUDITOR-480a54b4-bb9d-47e7-88d2-76a8dc01d359.json；ID：e41e6984-996f-4b1c-8dfd-2c0faecfee7d；SHA-256：9488033fc8efa833af1325f3554728c392a17e383583dbae87b649875aa411f1
- agent-AUDITOR-8b189be6-f57f-4c71-a663-42095311652a.json；ID：ce2baedf-470b-47d1-8736-53b67a24e07a；SHA-256：8428cb1d907ce5f3144ea166a47512ff31ebd4908afda082648eb2a796817cb2
- agent-AUDITOR-dc0d887b-d0ac-47e0-a38a-c2cf7f9c1f81.json；ID：45d57aea-9695-4ad0-bd14-c241e6eb849c；SHA-256：d910aa416ee5be47cec2d1a96d6cd48744bac4e97b4848d1261c662907cc5886
- agent-AUDITOR-df26974d-c503-43bc-b8b4-f9476baa0c46.json；ID：66c9cc7c-fa8f-41ec-8eb2-3a8978488e5e；SHA-256：79124f2a5972db317182ecd6060039b45ce2e05eb884652f8a00a5771b8c1d9f
- agent-PLANNER-eb94608a-e334-4707-8825-b57966029378.json；ID：ef8d061a-947a-47af-bbd7-5069ab49bd28；SHA-256：947b04f6151a3b55f1e86e31b3792ad817785fad9fa2ad68e6acbae6f4137caa
- agent-REPORTER-b438e618-48af-46d8-9725-67686824dd58.json；ID：46d0e069-cd7f-436d-b6a1-61ce1d4d5239；SHA-256：332e35caabbd6710c1cd53cb56036b9f0a350c21e59e7afd78291f46d835f27d
- agent-REVIEWER-0464290a-18ee-48c3-812b-a55000702370.json；ID：4c98003b-5a11-415f-b9af-2c3ee47ebcab；SHA-256：d7145281a2e25911ad9955d2644a97d7d67a5027da8691b11a3d8afad55f41e8
- agent-REVIEWER-2ca7c065-ba28-4033-a8a8-ba72f87cf1cc.json；ID：0920c6ee-31bc-4cfc-8e46-27f5e0ee3d13；SHA-256：a39bfa65a71afa52cfeb4847d4da277e0f5d5b4fab67cd4c1a9d60c219d1e53e
- agent-REVIEWER-3eb030b5-d666-4819-a299-b910e17d22ad.json；ID：22b826a8-e24a-4bfe-8e16-6578d36e81a3；SHA-256：6afc8681fa83729af3b0387eda80adbeae1e1bb728e12919f440803133b76fe4
- agent-REVIEWER-8a73f3db-4060-44fa-8940-fa476664615d.json；ID：974a72ac-e150-47dd-b89b-244c80d5ca7b；SHA-256：81c4c900f4948aba979f3cf73cd610fbbf47b835f0f556c72b6c487c6d75b3a4
- agent-REVIEWER-cc619711-9130-4759-a940-590955ae12f3.json；ID：4103e628-ca5a-4063-b917-351988de5c9a；SHA-256：1a5dfd32b3cdca361caf8efeb81d1d1102e270f0b1e91cbf039c87b23c93bdeb
- agent-VERIFIER-43bf630e-e581-422f-9bad-a49ade18e378.json；ID：566284a2-b690-4b20-965a-c07ec9039ebc；SHA-256：a5933b3f8d7ff80075ba33226120839e0b59b1da78353bc33b231ef00d36aee0
- analysis-result.json；ID：f31f8c3b-4570-4896-8a62-4df395c798a2；SHA-256：b367513d2541f0ef70ea92db1083b01ca52c74c98ee14bb7e22dbfa0fd5b50a5
- model-request-04efa717-fa3f-4fc1-88bb-d74b25233e14.json；ID：4131054a-a933-49be-925f-d1c27756544d；SHA-256：899081c54f5032893dcd3c8310e2ae07e979b0009d4d884229428812c9a3bad3
- model-request-12439ba2-97cf-4c0c-a27c-e405fec0bd01.json；ID：70ef566b-6c9a-4ddc-a1e8-f6ddef942205；SHA-256：5e6ba9a879d2a2f4d846c182fe6ad7559052065ee878af69de8ea5cf30241945
- model-request-1ed33d5a-33a6-47ac-a995-e94708845384.json；ID：2dc93920-e16c-40eb-bac7-c278e177a38f；SHA-256：4ef58a81eec2fd6400fa15fb2c35db719f5ce967944f545be00d1aa767a3a0fb
- model-request-211c8160-7f3c-49bf-9f9a-231b9e5073bb.json；ID：1a1ba581-4234-485e-85d4-2a7ab74082f9；SHA-256：6d93051399c6ff185351ee3fe2c12357f6ba9e7fcfa843cf389edd7a84e98ecf
- model-request-228e961f-0c48-46e4-a46b-92116095b849.json；ID：b6b41f2e-9a4a-42dc-8d44-ecf37133bdc3；SHA-256：c327a048d826217bc3836e7099b4c8efbc0e28e6bd6d57a0debd5335f6acf7cc
- model-request-22b4d411-28f0-44eb-8b80-76e8c6a57c22.json；ID：52d81c2d-2fa8-4fe1-b624-b69edfef1b0d；SHA-256：587b009f28ac3da2c53d0bfb529758892162028026c5d31c7a8aa45778f9a2d2
- model-request-2a0993e8-5fcd-4e04-8855-abbd018ed624.json；ID：3856b0ab-0d39-4cd7-a345-70d36d30366c；SHA-256：6c8bcfa70616eaa4acf8a80a34293b33f9d034a15c7c609fe6a8a480c9839a2d
- model-request-2a30adb2-1e66-46d0-bed0-3980a5377e4e.json；ID：49373ea3-ed57-43cc-ba89-6a5006bc5bc7；SHA-256：ca90d4c1429e8b4bbc353ea984152ccdffe6053382d580f127b2932f3db1bcb2
- model-request-2ad3883e-c769-4175-89a3-e05fe935110c.json；ID：6df3104c-f3aa-4fe5-ba0a-d211b7424d01；SHA-256：1ef1f2c0469f90ca19a5ea9b684ea9543fde44674b860d75e919f99ccc85f3bb
- model-request-2e198733-9134-4bfd-96fc-ce8db5400469.json；ID：d5f7cc09-f543-414f-95b3-649a2bae7b58；SHA-256：e77d9522dff40ed846a1ea61ae52e7ca045001758e6825936c6fc414b644731c
- model-request-30528ba4-28aa-401e-9de3-1f00eaf68902.json；ID：cc2f9fcd-e7df-450b-8ef5-a4c97298914b；SHA-256：d90baec2674db20c23b40b24ea74fcc4a0196dd8c5fc492d88b0511e995b35cd
- model-request-3c61b8bc-24e2-444a-b738-25d9646ad668.json；ID：f1fa0ec4-38da-4529-9dba-bd3f8a755c1b；SHA-256：4a9f70e9e5e5016b1dc4d729e7e04c428bbf8eec898c5ab06ac575ffaaa34c28
- model-request-3f22ccd6-15f5-4356-abf1-ac9771fe9f5f.json；ID：40d979e7-f894-4d35-aaa5-5d6e0bb4a567；SHA-256：0910efacd114abad0ab3d7999d6e2a18d35d78c5719c7095724c31cbf8d57001
- model-request-41baad40-5cc7-4b0c-9540-235102c57809.json；ID：0fe9bb31-8873-49e9-a348-88e7433bcc47；SHA-256：81beed3be0e83f5f43911233df527de8ee214fd24ee665a1fb844178b3323912
- model-request-42dd2bd6-11ff-47fb-999f-8248d4f1f8a4.json；ID：9bced61f-ba88-4a65-81ca-9a6c5f502588；SHA-256：f1f2b4ab65feed492010423c3ae107e4f2dbb63d229674820acf7fbebd64fdbc
- model-request-46707e55-266d-44af-b453-220c37954ebf.json；ID：5fb8bb77-146c-482c-a293-a0300e04f81e；SHA-256：a9f1808c4176b82ceb551be665d0cd5fde0995257d4e785065cef31cc337377e
- model-request-470e5ed4-0a7b-4e7a-8eac-4cc3784ff7ad.json；ID：23afceb8-0f3e-41be-8437-1f3f0ff7cb13；SHA-256：bd278ce141cd47ae653781690459365f6f79783669de9e1d61633b52b7da408e
- model-request-4bcf98aa-d90b-4ce3-9167-47629e6a8979.json；ID：e051efe1-d969-4fbc-8bb5-7c995ad33305；SHA-256：7c7837bb3c45783861171c98949666f6be8a8dec614443d134a91d45533036ff
- model-request-4efbfa7a-c961-49cc-a437-25f36ee780b1.json；ID：16402a4e-4b86-4a94-b168-b6d25c72d8a5；SHA-256：f28222f4a27cd288fa50e7be426b2e77cf4170ecfedf783e4565fb0dba1186ce
- model-request-54962eac-3966-40d6-9819-17be54210f76.json；ID：566b7fbd-da98-450a-b42c-4e4826b754aa；SHA-256：d4ad869287ba269dbbcfb4a0ff1e4a256343b080d25681f9abe37830e0410b20
- model-request-561aeeaa-3280-4d25-8632-4ea5bb636029.json；ID：0d511e0c-d9fd-43c7-b2e2-a634a08e1dd9；SHA-256：a33e37b562dd10c963c507c1e15054f8a4fbe254a8253f53271410e54a52048e
- model-request-58a3956e-d01f-48e1-bbc0-cbaffdf28bc5.json；ID：4ae4c354-6833-4f35-ae6a-506d431c3af3；SHA-256：6a25ffb63c704c7c34a90490c3cd6809a0566351b012d4352e726fdc059a0153
- model-request-5a5efeae-606e-49da-a566-aee7d79af5da.json；ID：4b077f28-d926-41e5-9f98-15b71b360ed6；SHA-256：2009bec4f15656801759c63b4742a78640a816a7d29840bd614b4be1bbf25850
- model-request-66b81213-d554-41b5-aab7-bcfb4634c856.json；ID：4f73cd78-b19b-47c7-81d0-63a534dda020；SHA-256：16ca62d7ebce45673bd00cf665187ee632c7c03523c462e8b7e46c9078465792
- model-request-6783a993-0622-4d34-a122-b42abd001d46.json；ID：35eb42d1-ebff-4942-85bd-86ed2a8713e0；SHA-256：1dac9f57f23fd8ccc407cdf7ae0e49240d50d6f9ea7164c6614f344d48c00d6d
- model-request-68d1de58-f433-46c3-8cd3-499fc5fc87b0.json；ID：cb59965d-dac4-41b8-a8fd-f5e67a7b50d6；SHA-256：22a189dab2fa4b0be63c1767309a6bb2c09ddc6a450f9f7bb87403a0e359fbe6
- model-request-6f0f410c-f946-49d5-9524-3d5b623e504e.json；ID：df5a43c7-264a-4fc4-90a5-40bd410ec31e；SHA-256：d7c296151e898f97e55ad93687a520b8cb3c8043b96548c9b0c10334b384c4bd
- model-request-6f33e90a-2a83-47bf-aa95-4863cfeb3824.json；ID：a0e6175d-2161-464f-b833-bd2f5a05f842；SHA-256：f159c6112fc9743aad679af38209b5600d88a526230b3261b5c4f60b35bc1b66
- model-request-747a1381-9296-48aa-8098-6244ad65162b.json；ID：33cf5504-ea57-4546-aa24-10b9210d85db；SHA-256：b93847af1efe55fe21b18964b4fa31931c43194d5af5c13c29b89aa236547245
- model-request-775f412c-8167-4d82-b5b1-283a28b93d34.json；ID：95957e96-31eb-4107-b962-a037d677e801；SHA-256：6ad723e992a57eee0fddcc4beb12a81e3aa2372079d5522b3387bb60a64f8109
- model-request-7a002b45-f06e-481c-858f-76175ba84ef1.json；ID：f30266a6-97b8-4a61-a3e8-547392a8e9f0；SHA-256：4ea6d9dd07e09c4cc8377cc26ec40235e90406d4b89e1a0f6e6028d022f868d6
- model-request-8062c32f-a36e-4773-836b-4d3bb882a95c.json；ID：08b35da4-ed74-48bb-a54a-8ca7ffcce530；SHA-256：4bdee852e98410689aa879b946fc6c067437c075a9b778500d5641dfb7b23d73
- model-request-83266fe7-e1a1-4d5d-97e6-b649047f0697.json；ID：bb908567-27d7-4f46-af62-2f7886a4f907；SHA-256：b0b365eeda9bba8d6688b3c30d20738d35ecda8cae789ce2ff0d8e42ab63bcaf
- model-request-85228733-45fc-45fb-acd4-7ddb19be1425.json；ID：6f148d52-904c-4ef7-ad6b-3aed68bfb4e7；SHA-256：57d529c23beade63615c9918d49e823e18f04b0831b8e3ec0575c60e0498128c
- model-request-85a4b608-9e31-4e0f-9146-0ebfe8b6e3f7.json；ID：b2ee824a-149a-46e0-b3de-f32a01506e23；SHA-256：1eb9c1a6f3c30c157c3a888a885322e1b9748ec3b2f89950acb30d4d05147171
- model-request-876b3768-1e15-49a7-b772-44e67489ea42.json；ID：e6802d10-029c-426d-8fe4-5fc4bf952c13；SHA-256：69bd8a3e3868cc6f87a6539ff004ca7143b2a2425bc9292e33659e0d790f7e0a
- model-request-8e4f3874-c447-4702-a639-871149789a77.json；ID：3c105875-869c-4d75-868f-12794fd4a224；SHA-256：d8bbf2b0b52ce9582cecedc3b34d582c964cf86acd774b93a65744be109c4bd1
- model-request-9291288c-699a-4530-a392-aff871dc32be.json；ID：aabf4beb-fb87-4e20-8deb-2c6dbdc869c1；SHA-256：1ca2c27e9657e2c0b4daa600bb35e86008de8b8e5dece677e97674e11eb83a82
- model-request-99fd3be2-6a6b-40b4-9f94-d84d382159a3.json；ID：b6dedf16-bb0a-46fd-9b7a-8b24e2fc0ab7；SHA-256：ff3d9c17206810e6c0d3349e8693db7697ae39f636ce639f648582d67b33dcb5
- model-request-9bcff67c-84f6-40b8-a333-57431c4791f9.json；ID：c5d49964-4c36-411f-9c6e-cba257f81d83；SHA-256：1837a7b09ce95e72ea3090359042e7bd17a5b858aaa6a2223951ba282bead278
- model-request-9d66095a-9a55-4cee-9c54-3f9dca437bce.json；ID：88ec6b98-0ec4-4ed5-b51b-c37860d14c69；SHA-256：c11c65f9affa7b29691a6094e88d3167d6a3c56ae21124b24e47989f420dec49
- model-request-a2dad64a-0697-4997-b320-fdc0dd5d7139.json；ID：fecb4bb3-425a-4c31-840a-347e3aeb90f0；SHA-256：e13fb8e89f8ac066765306891a860529e9631a7cc98ea4730baacf57c1e1c95c
- model-request-ab025ac4-cda0-499f-87c4-8d970e0a79f6.json；ID：b86bccf2-e80f-4e78-beb6-a071d4547ed0；SHA-256：e7fc558ef93f0319233b5781a80556a8c4a7e0a67c7b4a7edf62c7bfd3c3bee9
- model-request-ade0e571-2e20-4fa3-ac71-62a5baf180b0.json；ID：b72db10a-caa2-4a18-afbd-8207530f8d6d；SHA-256：d00206d4009787e15ee004e0f83d2330e018c713c790e3ea24104f99bef6399b
- model-request-b32b9ff1-789c-4a1a-bc42-33f509e1bc6e.json；ID：5d2f507b-661d-41f5-8ce6-a6a2e18e0d91；SHA-256：36f51cdd92afce1395ef2109fedfd529129790eecbf74edf04ec6d83335ba97c
- model-request-b66a455b-b9ad-4fc4-b04d-8547fc6768a0.json；ID：cdb01234-98a3-4ea8-8378-cca439846412；SHA-256：447ec437c789512742d006ff96c022d8edfa3f521e3a6999692b499900f0d825
- model-request-b8513436-5847-43a2-90f6-3b216b4bfd7a.json；ID：755af85f-6ef2-45fa-a811-c2856414fde4；SHA-256：7c6a8b7eb67dba8aa9c5b14beaa2ffe7b18bbcba43d989b08dd05fe0564da16b
- model-request-ba21d9ef-1a97-49f4-bc6a-a4ea2aac4eb6.json；ID：020592dc-ce95-4cf8-b7d1-0f0b4ea27722；SHA-256：8f4bb72205545fb5876080f0576efb935dca4d89705f64d1048eb35ebfed42d9
- model-request-be234f53-22ef-4734-9ea1-f7a5bc257675.json；ID：bfb5d09a-0d7c-4557-b78f-77fee48bf94f；SHA-256：178ca3b0c5f065eccf860d6d2430c402f526518f08b37200cc88c274ed7619d6
- model-request-c8a4d3b9-0f1e-4b90-a50b-7213b1100142.json；ID：03303d2a-61ca-45e5-adc7-68fac68fa697；SHA-256：7c0f74e6d7e1d5b4782c782d681c83e3716db09ea5cd186e645d7ad642800136
- model-request-cad51081-4153-47a3-9c98-6d5dafddf144.json；ID：64d24424-3782-489c-a614-48b27cf9202e；SHA-256：135be1f1c6e7be1ed705a9d10b4d07992104388ba0ecb1bfe0c5ce58e0976570
- model-request-d20a808b-321d-491d-950f-c4a50d236d33.json；ID：2573934e-2db6-4022-ac86-b5019cd1e1d9；SHA-256：5f73fa434a4811c3f99d87d0bdb3c420dab63a094a3e6c95a70f30e711dc245c
- model-request-d2b2a77b-58b1-43ea-9c7d-c628dedc8d7a.json；ID：46ce55b7-da61-4c39-81df-0500689db2ac；SHA-256：f21808473a3d1697f8713c342d91b6b2aa133d3a3cc71b6754fccb20d775798a
- model-request-d3133493-f15a-4f22-aa08-a143d281f362.json；ID：5db300f8-6935-4025-9f29-59b217c16d71；SHA-256：6e73c34313cc74eb0ce4696f47be5d036b020217c4e66973b545cf777e5ef120
- model-request-d54cb772-30b3-4619-89eb-53a063571ac2.json；ID：d9b8550f-1f75-42b0-ac70-93a83a0e07b1；SHA-256：7dcc221c1942bb96db980a7785ceeb24f3f623a6d7cd782e6522a8aff03a8508
- model-request-dda11f4c-bc7f-4ce8-b94c-36dc39ac70bb.json；ID：e20ea628-877d-4392-9e4d-dc653bcd71bc；SHA-256：10001c75fafbda581392b01523ac7b944e639305db6ae638e6d24544eb7909ac
- model-request-e6e6c4f6-8077-4104-b28f-a8e6fc92732a.json；ID：8a87b451-3fc0-41c8-b71d-5ea524785d4a；SHA-256：ba828c67fc2a09790f341f6a353dc203160b44714b19589d6e24feaddd8b808a
- model-request-f25b085c-d68b-40e5-8d1b-96d6c60be99c.json；ID：fe94e235-c91a-4c81-86e9-453b6cc28bea；SHA-256：10879e1d35bd0f50e2627edaf4d5ecc525a035c9618929fd52df7021f3f55c9e
- model-request-fca69a3c-8f37-4c47-b80c-0847c9459995.json；ID：d99b34e9-3ce3-4425-86f3-d37e00df1f12；SHA-256：872d6ebb829f1847fc71a5a689053e6263f256539d6d8500fb3d167b0994a454
- model-response-0408ba1d-d380-484f-a829-eb05585580c7.json；ID：64b8b5f9-be50-4e04-b236-6ef213965f34；SHA-256：a220a0a2b3a8004527bc7ae1a6bb0d38c571be8f8f066581f7cdb23171d2a4d1
- model-response-0c79266d-af8d-4c05-92d9-cfaa755ec0b4.json；ID：932dde46-2d30-467b-8d73-70dd7e377141；SHA-256：00e792329e66c48c9b48e3ea819fdcf7c4eeabef38437954820058084fb54036
- model-response-0e3c987a-6504-458f-9ea5-31aecc94fd07.json；ID：d56f3563-32ce-428f-b36d-7c442b09f89e；SHA-256：e0dd62eca1bebd26636897f5cbc94be95a002153b749caf5c321f9cb2a1235d7
- model-response-140a8397-850c-4101-aa13-eeb6758e0a61.json；ID：71bf11f9-1f48-423f-907b-85fdcd2db6ff；SHA-256：e5d954aa0a8a875e049c768eb07732734b299bf5735a959728051d2054237320
- model-response-171d2193-8dfd-4e8a-8f93-47d3869d4d15.json；ID：3b32aeb1-78f9-43c8-a6e8-54da717ef387；SHA-256：808970f7d9349e7bfeb72ee2971035b2f1ddd578e24e3617eb488095471c7974
- model-response-20f5a775-8759-4ec5-bc20-de75307a8f93.json；ID：3e9c72e3-bbd7-4f3b-aa49-6a42b39af386；SHA-256：cc8776835443e6cd3b284457b071298b989211e8611c21c1becf3a6bf904f403
- model-response-26dcb032-3c70-44a6-8045-4a9afd59a8c1.json；ID：49ba2b9c-9a1d-44dd-81c0-9e65fd777366；SHA-256：b92dcef343d9492b0db7bd06ce7afbe6977da91097d02237511fa6eb13b88e38
- model-response-36e97ad0-73b9-4eb9-915e-2ed065c7100e.json；ID：a8e0eeff-af1b-4662-a22d-b972287ae3ce；SHA-256：8bef242e4951fdb24c33a4586509fa15b3adf888984bc9ede63f0912325fa661
- model-response-46018be6-c5be-46ba-b855-bebccfc94aa3.json；ID：bc5d9d89-4760-4a9c-9288-e5b7ec401074；SHA-256：0da9e5a42e14447762f478dc3f2d4fade5051b40c1127ed930525e7f036680e8
- model-response-4b0f8f47-d8d3-4fbf-874e-505cba53ab58.json；ID：08267fa2-c969-4991-beae-668692809576；SHA-256：a8334ddb60dd1d31134b360d6d5b9561a7288df750b33f4b77b74e5e7cbcdf26
- model-response-5730b67b-b7d1-4681-ac76-5b3aa9541fe1.json；ID：586660bd-e8f4-4c70-a4cf-bc0c13c37319；SHA-256：9d77e5c457d9c8ffa7746b6d12f26b61f9a1649fe71188693a939e022c817066
- model-response-61d9fd2a-630d-4800-8d5d-c706f7eb5e88.json；ID：ea3c7e5d-e8ad-4a59-be54-76650f385fee；SHA-256：d9f7babd967e3da76324f83ef1c840df8dd192a5a3f630a514da67ca2a6ba5bf
- model-response-663cf910-a0d2-43f6-b6e0-dd49f1e5ed2f.json；ID：ff3b2360-97dd-4e39-81b2-d2fdc16dbf1b；SHA-256：dd1a26797a19a6339133d298de679ba87a428f62ad41c5f9762fbc70f52eeed6
- model-response-66944e01-56f9-4b3f-89b3-07065a51962b.json；ID：bd3b342f-4a0f-4af0-9858-64b351592ab1；SHA-256：8de994bb2de1532992535cea81a1a3c4ab2ec62b7738d56cf08ea2d320c0fec9
- model-response-6a49c923-0eb7-403c-9b4c-832746b41619.json；ID：6d3c760d-8e79-4b55-b57b-9ab68a83b558；SHA-256：712602163ee8021a16da68e1663f73baa352289a06129718069e544e193b29cd
- model-response-6b14395e-20e1-4e0c-ab28-a0cc9635a774.json；ID：08cee89b-0002-4be6-a657-1d24d39b8443；SHA-256：0faa86de2802bb8bfff7c284a17c0d76f1eae3d250b308a0bdf41ba786875982
- model-response-6cd59cac-ad31-4d2a-a59c-96af08876266.json；ID：0f296cce-4ca8-4751-90c8-ccd84bb9e3bc；SHA-256：47012f37a068c13a6ab4f3a63c241454f1ddfcd8da8403044414c7441a42136c
- model-response-6f4db97e-411d-4b0e-83d6-0dd73ea38f3d.json；ID：f73bc8c1-ccec-44a2-9fcb-2d5e252aa40e；SHA-256：2f455dafef9dea246519cb39b8016c6e6540fd304dbbf1efa33945b26967d1b3
- model-response-73848361-6810-4863-b060-4fc601d46827.json；ID：dc469d96-9a9b-4949-9dfc-ccf3aec585d9；SHA-256：8d42b7ca620275d2e061324daf5804d21f8d71c99240556eb205ac22ff1f25da
- model-response-73be4649-c6b0-4e0d-9c20-24e4fe536246.json；ID：2618507c-0367-410d-a11b-d2b12c82b932；SHA-256：48574f58fa2e16232026c12146a26cef1a7a8149942545ec2e2d58077221c21b
- model-response-7726f548-afe5-4809-be41-c8fff27f811a.json；ID：5d93c5a2-c4ad-43d2-be34-d70e4feb8878；SHA-256：dc9c604c6ef8690f8bdb470437886506dbdd98440dd86c5fec6cd9ad50aa4cbb
- model-response-77b9ec7a-4242-4a52-a929-355f7cf8a0ca.json；ID：990114b7-a0ea-4eae-a958-72efc373eb9d；SHA-256：abfb1d509737a060bce4dcfbffd1aead31bf3051ddd57c9e2a98b81f9a677bf9
- model-response-81febd48-4b5d-4809-bdaa-951541a3c861.json；ID：ea49c93f-13fa-4eaa-98f7-ffdcf67cc3d8；SHA-256：733d8d1ce6b3df39f8d17a2c658dddd459ace5b18661f77d4f06d52f6872edbe
- model-response-8477b219-afdd-4c4e-af07-42f2434490d8.json；ID：1effc218-89a1-4dbb-b02b-b9a1e1eec4ae；SHA-256：8523b8c6ef4e9c1f476b977072642b6fb4a208a491fe2ab29b1655aae4d3dae5
- model-response-90a6f964-2e76-4b6c-ac02-b9181c2f6c45.json；ID：2e42e754-d509-4fec-85ce-ac8877c692f1；SHA-256：70e04945ac65d6d663aa9caee6102ac43664fb7af6c964bac3a9a1e8f222a48c
- model-response-9847d9ce-b3b8-4ee6-8ea1-d64cfb38d8c6.json；ID：e30c711c-bd65-4f38-bed5-84082108663c；SHA-256：5a47685ba1eaeedcc5f110b7595c212521b5b1ff22b685864f8fefafda5f56af
- model-response-98567c1c-879f-4870-8bae-8861928fec67.json；ID：3513c3d5-00a0-485d-998b-d25426c95cfc；SHA-256：dfeaad7b3b638bf9735683e325c5c8f8add058bd22ce8b45cac8a283f13d62b5
- model-response-9a19e31c-b4cc-4e7a-9ba4-700262d59796.json；ID：f1d53343-d81d-4b2e-b1c3-8557c56be34c；SHA-256：bcdd6b1d47600e6c412b0af12220b0a2ba59206a8698db84923dfff39abae6ff
- model-response-a071d431-8690-40f6-a408-9f6f1bc861d8.json；ID：6ca17190-55f4-49b1-82d4-d01de257c38f；SHA-256：ec23a5ddefc259677b3dc88ae04ce0f2cc81e24c7c6f62eb6758ba85eaec4846
- model-response-a4a7274d-269e-4bcc-9f5a-c8f60e6cfac7.json；ID：f1e1e993-5772-422b-ad18-ae5178568a15；SHA-256：39b554cac0d20f54a3fd155628e8e7d5c8d7727fd07f7fa05517a65f5e16dcc8
- model-response-a4cf36dc-4912-4ea9-bb85-e753e06746e7.json；ID：5a927366-b3d7-49da-9251-3fc59d7b9867；SHA-256：9132639aceb80922d8f66646066c3cca13b3299d5792c521701d280f4c1d3632
- model-response-a64c153b-c9cc-480c-9ec1-132297d6c9bd.json；ID：f6f7e3e5-1041-45b2-8ee8-96aee6568255；SHA-256：42044b12a9f32099402968447bb342b7eaa1487123bad73beb578d1d06368893
- model-response-a9d6ab2f-608e-4027-a69b-f15b231aba48.json；ID：5a7a631f-ca04-4040-ac57-4770f89a2c8f；SHA-256：cbda2689bfa8988f4da47f621d9fe9da26485b87ba54797a6c8c56d141d702ae
- model-response-af26e9bc-c5c5-4d7e-9c0c-e5cad9f19f5c.json；ID：0d7699d1-be60-48f0-8553-124f7ca65cce；SHA-256：eab4150fe6e0c6a653eb6fa01ae14834cfdbf9466e717792744c94ed4ad9ff97
- model-response-af7ffb53-39c4-4d00-891c-f15128756e4e.json；ID：5a3ab679-0603-42c0-a6a1-d8c80a6f91fb；SHA-256：86f4f7149be06506c24fe09fceef9bfab1d1eb205755141c2ada26a48f0b8e01
- model-response-b30c655f-8a2c-4470-81ee-7870c9e1ec33.json；ID：59199d17-72ca-48ac-b3c0-c3855a7e3c4b；SHA-256：4f940272f2d547461b42c0c4f3a4fe1b3b600074f61b38b75b4750167f961367
- model-response-b3515b01-68e4-4b1f-993e-370cd1e6ee26.json；ID：9ff8ec21-9d3d-4f90-a59e-08e085ced105；SHA-256：bf3a76bd1356faec411ee261e853fd67560dfe30fd204db00f59aed117a28ed4
- model-response-b4fc7845-297d-43b7-93c6-247606be06ae.json；ID：9463f596-b6fd-4bba-800f-1495e28221b9；SHA-256：b11066a36e95de9db995cde0c96ae3f70ff4dd0eb05fb4e37addf0e14037b9ec
- model-response-b53c5233-6fbe-4164-830d-1bd4d9241fe8.json；ID：9bcb27af-aa31-46ff-9c62-3785f8589ef6；SHA-256：8a7208f85cc4ffa1d1b57328348403d790b2fd12c59313281a5259b59ccd622f
- model-response-b6f12d3a-982c-48c5-a78b-0007e1509ce5.json；ID：e66740ea-4d90-4378-a2cf-a424cc662946；SHA-256：b5ce43f2db33c9f58356c7f2c6452593659c4146bffeece6d8f77886d14f8075
- model-response-bc44ba07-2bef-46be-8a5c-6780dc2bd8eb.json；ID：e997afe4-227b-479b-823c-25896d7d2e7e；SHA-256：ee3951f1485bf58a69aa76a6007d9d6a048c4361938e49308acf70c0b3fcac86
- model-response-bca62b1c-5447-4f30-8fb6-664f3fbe4d68.json；ID：1dd5a9f3-c3ed-4870-8c72-bd336a2426a1；SHA-256：97aef034cbab09bcc608eeee32e93d31afd3f31769b7992e4729d471c6c2b8ca
- model-response-bce730b1-88cd-4c13-95ce-391a1bbc14c7.json；ID：e08627d0-18f3-428b-82c6-cb6a803fc70e；SHA-256：714483340b9c6fb16bd57c9e261ffcaaf9765d7f426ae3333c1c52c7a80e21a4
- model-response-bdb9de7b-735e-4da2-9b4e-be8e933b955d.json；ID：5c231ab6-8635-4b5b-9944-fc14154d8dd3；SHA-256：e0a7b6573d9b6104795bc5ad5a329be6bea45a03c17828e6fdaca9212a7367ab
- model-response-c5e7bfe0-f533-4a74-80b3-2295ae509c88.json；ID：055f124d-3a4f-40b2-8370-c4db64cd2a1f；SHA-256：06475e57d0ab0499d22dd953b1acdc4335c71555150905a0e86879fb5532a18c
- model-response-c7083e76-0a69-460e-8a91-6963cc736080.json；ID：dbfc80f0-c78b-4736-9eeb-5b8c639ff2fb；SHA-256：9e296368982ab8799012912af2ebd875b1b1272c0b5e80ee344fddceeff961c1
- model-response-cc24fbaf-f93f-4e05-b9d7-f246089ad24a.json；ID：05f04ee0-e21c-4a57-b783-68af7c4e0a1c；SHA-256：97d8100903a1def7522b9b5031c36be4eb7d6cad5b476673ee7edd9ab082d3fb
- model-response-cfa8713c-b04e-4916-8547-48308aeca6a2.json；ID：ab798549-0f60-41b0-93ac-5890651d9720；SHA-256：0eba550cc65eb3c4e9474bb1208e7e7079b5077624ee88da3d1483a4623b4744
- model-response-d8ec5f71-72da-407c-bc20-94c6b93ec5aa.json；ID：74c5a48e-a09f-4dc8-b658-c082047e336c；SHA-256：01b17df84fc1e97c6150164de19a68e946f6abb0cb998c82edeb06b2d0fec48a
- model-response-e181bd5a-585d-4e42-8e92-4df41d647377.json；ID：bdb9cd15-1360-44df-9433-f9b4fc7858cf；SHA-256：c24600692c839cf5d04566dbe9c4fe3c454e42dca0bd6164314e512f6ae6ea2c
- model-response-e764687b-76d2-4de9-85e9-ad55da169847.json；ID：06b5e7e5-ff32-48a8-b10b-b670c763ab1e；SHA-256：b9e7602e165593fbc7eb414b79d2ee5f9b24302aade24e2920689e0a0bb3f418
- model-response-e77cceb9-164c-4c39-a902-94c1b90cd4d5.json；ID：3aa664dd-e75e-413d-891d-b71b81c993a2；SHA-256：42f8b8bcab8467f7b533d990686910a41cbbf0ebee551de654b28e3c26da4fdd
- model-response-ec085554-4240-42f8-a917-ef61febedab4.json；ID：d5333b0a-e696-4371-badc-06776c3deb6d；SHA-256：4f789314eda01ad71e3de4bb8316da836b12a75516113350f81fa374c893b9d8
- model-response-f1eb19db-5419-4c4b-b013-db3a03f49262.json；ID：98350dde-c0de-49fa-9c9c-31d23bb20cb0；SHA-256：4788ef3a7e60f388585267df7e1864bba836ef73978675e93f9caff4441c8d95
- model-response-f2b4203f-e58d-410d-88b4-f9ff7151269b.json；ID：bb84b6d8-5b7f-4afe-bc0a-41d6522211ae；SHA-256：cd641eb234bdc0a73f88895e09e9d4e479823190583fa808e66102b611b76f35
- model-response-f5c4871c-1fec-4882-a48d-4cb91c42f996.json；ID：d03416ed-7e80-40f2-b587-389ddf893ff9；SHA-256：a95644d832b214c86957e9cc2cdc35fb97101ea0c475f3263fe297d8adaefdde
- model-response-f7809323-df7b-4af5-8795-5ceaa807be82.json；ID：6d862ce7-4b0e-406d-a44a-c923f9590d2c；SHA-256：f9cd667ec60fb146ad3c52a5f36802d75f21cec89e062071ce4797235421a766
- model-response-fa4ad5fd-a4f0-4c42-82ed-bef5ef9fffa3.json；ID：3614d273-6227-436e-a05b-316bb169bf3c；SHA-256：3b6f344176015d79105384d6a9d7f5d84d5af3ec16083def7818102918392d53
- model-response-fc71caad-6900-4bb0-9003-f3ac8fdcd307.json；ID：0ba79918-9ec5-4e81-8cbf-5d769edf87f0；SHA-256：30472f049ce3e1dcb5e9a74b107cddd9ebf8547ae6b660c469c55a765669babe
- p08-ollama-authkey-fixed.zip；ID：b9f09308-9154-4916-8d1c-63e3f2c606c8；SHA-256：442ca6b1cbeb89bee07b136c19791d968ed64d193e51da3f0815f55f1cfec0d5
- snapshot-manifest.json；ID：6b94a6e2-8346-481d-8499-492d0edb43ea；SHA-256：cfe49c3a1c40d11e57780f70fe6b4e82701795b3574b02198211584dd3ae9bf6
- source-snapshot.zip；ID：64231c95-d00d-46b0-8334-5b6d7944a0f5；SHA-256：5cd036c891bc32e535bfbe8096e250b29ea0b7cd2b34609e9665af1620207827
