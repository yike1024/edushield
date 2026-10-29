"""EduShield RAG 安全知识库。

M1 实现（16 号方案 B0 修法 A）：知识内置为列表，检索走关键词打分，
不依赖 ChromaDB / embedding 模型下载，重启必好、演示立即可用。

知识域：
1. OWASP Top 10 — Web 攻击防御
2. ATT&CK 技战术 — 攻击手法识别
3. CVE 漏洞 — 漏洞详情与修复
4. 等保 2.0 — 教育行业合规
5. 校园场景 — 教务/一卡通/图书馆专项
"""

from __future__ import annotations

import logging
import re
import threading
from typing import Optional

logger = logging.getLogger(__name__)

# 内置知识（seed 33 条）：(content, metadata)
_DEFAULT_KNOWLEDGE: list[tuple[str, dict]] = [
    # ── OWASP Top 10 ──
    ("SQL注入：攻击者在输入中插入恶意SQL操纵数据库。防御：参数化查询、预编译语句、输入验证、最小权限数据库账户。",
     {"domain": "owasp", "category": "injection"}),
    ("XSS跨站脚本：向网页注入恶意脚本在用户浏览器执行。防御：输出编码、CSP策略、HttpOnly Cookie、输入校验。",
     {"domain": "owasp", "category": "xss"}),
    ("CSRF跨站请求伪造：诱导用户执行非本意操作。防御：CSRF Token、SameSite Cookie、Referer校验。",
     {"domain": "owasp", "category": "csrf"}),
    ("暴力破解：大量尝试用户名密码获取访问权限。防御：账户锁定、验证码、MFA、速率限制、失败日志告警。",
     {"domain": "owasp", "category": "brute_force"}),
    ("文件上传漏洞：上传恶意文件到服务器获取控制权。防御：文件类型白名单、病毒扫描、限制上传目录执行权限、重命名文件。",
     {"domain": "owasp", "category": "upload"}),
    ("命令注入：通过输入注入系统命令。防御：避免系统调用、参数化API、输入白名单校验。",
     {"domain": "owasp", "category": "injection"}),
    ("敏感信息泄露：数据库备份/日志/错误信息含敏感数据。防御：加密存储、访问控制、日志脱敏、最小化数据收集。",
     {"domain": "owasp", "category": "data_leak"}),
    ("DDoS攻击：大量请求耗尽服务器资源。防御：流量清洗、CDN、速率限制、IP黑名单、WAF。",
     {"domain": "owasp", "category": "ddos"}),
    ("目录遍历：通过../等路径访问受限目录。防御：路径规范化、白名单验证、chroot隔离。",
     {"domain": "owasp", "category": "path_traversal"}),
    ("不安全的反序列化：反序列化不可信数据导致RCE。防御：完整性校验、类型约束、白名单类。",
     {"domain": "owasp", "category": "deserialization"}),

    # ── ATT&CK 技战术 ──
    ("T1566 钓鱼攻击(Phishing)：通过伪装邮件/网站诱骗用户泄露凭证或安装恶意软件。防御：邮件网关、安全意识培训、MFA。",
     {"domain": "attack", "technique": "T1566"}),
    ("T1059 命令与脚本解释器：利用PowerShell/Python/Bash执行恶意命令。防御：限制脚本执行策略、AppLocker、日志监控。",
     {"domain": "attack", "technique": "T1059"}),
    ("T1078 有效账户：使用被盗或默认凭证登录。防御：MFA、密码策略、异常登录检测、定期审计账户。",
     {"domain": "attack", "technique": "T1078"}),
    ("T1110 暴力破解(Brute Force)：重复尝试密码直到成功。防御：账户锁定、MFA、速率限制。",
     {"domain": "attack", "technique": "T1110"}),
    ("T1003 凭证转储：从操作系统安全机制中提取密码哈希。防御：Credential Guard、LSA保护、最小权限。",
     {"domain": "attack", "technique": "T1003"}),
    ("T1021 远程服务：通过RDP/SSH/SMB横向移动。防御：网络分段、跳板机、MFA、审计远程登录。",
     {"domain": "attack", "technique": "T1021"}),
    ("T1190 利用公开应用漏洞：攻击面向互联网的应用。防御：定期漏洞扫描、及时打补丁、WAF。",
     {"domain": "attack", "technique": "T1190"}),
    ("T1041 通过C2通道渗出数据：将窃取的数据通过C2通道传回攻击者。防御：出口流量监控、DLP、异常流量检测。",
     {"domain": "attack", "technique": "T1041"}),
    ("T1486 数据加密勒索(Ransomware)：加密数据并要求赎金。防御：离线备份、终端防护、最小权限、网络分段。",
     {"domain": "attack", "technique": "T1486"}),
    ("T1592 信息收集：攻击者收集目标系统信息为后续攻击做准备。防御：限制信息暴露、监控异常查询行为。",
     {"domain": "attack", "technique": "T1592"}),

    # ── CVE 漏洞 ──
    ("CVE-2021-44228 Log4Shell：Apache Log4j2 JNDI注入漏洞(CVSS 10.0)。影响几乎所有使用Log4j2的Java应用。修复：升级到2.17.0+。",
     {"domain": "cve", "cve_id": "CVE-2021-44228"}),
    ("CVE-2022-22965 Spring4Shell：Spring Framework RCE漏洞(CVSS 9.8)。影响Spring MVC应用。修复：升级Spring Framework 5.3.18+/5.2.20+。",
     {"domain": "cve", "cve_id": "CVE-2022-22965"}),
    ("CVE-2023-44487 HTTP/2 Rapid Reset：利用HTTP/2协议实现DDoS攻击(CVSS 7.5)。修复：更新Web服务器和CDN。",
     {"domain": "cve", "cve_id": "CVE-2023-44487"}),
    ("Nginx 低版本漏洞：Nginx 1.20以下版本存在多个已知安全问题。建议升级到最新稳定版并配置安全基线。",
     {"domain": "cve", "component": "nginx"}),

    # ── 等保 2.0 教育行业 ──
    ("等保2.0 教育行业：高校核心业务系统（教务/一卡通）需达到等保三级。要求：身份鉴别、访问控制、安全审计、入侵防范、数据完整性、数据保密性。",
     {"domain": "compliance", "standard": "gb17859"}),
    ("教育信息化安全：教育部要求高校建立网络安全责任制，每年至少一次应急演练，落实7×24小时安全监控，日志保留不少于180天。",
     {"domain": "compliance", "standard": "edu_policy"}),
    ("学生个人信息保护：根据《个人信息保护法》，学生学籍/成绩/联系方式属于敏感个人信息，需单独同意并加密存储，泄露需72小时内上报。",
     {"domain": "compliance", "standard": "pipl"}),

    # ── 校园场景 ──
    ("校园网攻击特点：宿舍网段流量大、设备类型多、学生安全意识不一。重点防护教务系统、选课系统、一卡通系统、图书馆系统、招生网站。",
     {"domain": "campus", "scene": "network"}),
    ("教务系统安全：需防止成绩篡改、选课舞弊、学生信息泄露。建议：严格访问控制、操作审计日志、异常登录告警、定期数据备份。",
     {"domain": "campus", "scene": "jwc"}),
    ("一卡通系统安全：涉及消费和门禁，需防余额篡改、非法复制。建议：加密通信、交易签名、异常消费检测、物理安全。",
     {"domain": "campus", "scene": "card"}),
    ("图书馆系统安全：防数据库被拖库、电子资源被盗用。建议：部署WAF、定期漏洞扫描、限制校外访问方式、电子资源访问审计。",
     {"domain": "campus", "scene": "library"}),
    ("招生网站安全：高并发期间（志愿填报/录取查询）成DDoS和篡改目标。建议：CDN加速+WAF、静态化关键页面、篡改监控、流量清洗。",
     {"domain": "campus", "scene": "recruit"}),
    ("校园网常见误报场景：学生宿舍晚上批量刷课导致大量请求≠DDoS；图书馆开馆时段密集搜索≠目录扫描；教师远程办公访问内网≠异常登录。AI需结合时间/位置/行为基线判断。",
     {"domain": "campus", "scene": "false_positive"}),

    # ── 校园反诈知识包（T1-5 / caoyike 正式 23 条，2026-10-18；PX-021/PX-025 占位待网络中心数据）──
    ("刷单返利（兼职刷单）：以'兼职刷单、点赞返佣金'为名招募在校生：先小额返利建立信任，再以'任务未做满/账户冻结'为由要求大额垫付，最终无法提现。校园语境识别点：招募渠道多为班级群/兼职群/私聊，话术含'日结''无需经验''学生可做'，收款方为个人账户而非平台对公账户。",
     {"domain": "campus_antifraud", "id": "PX-001", "category": "scam-type", "role": "detect", "keywords": ["刷单", "兼职", "返利", "垫付", "佣金", "日结", "任务"], "severity_hint": "high"}),
    ("助学金/奖学金/补贴发放诈骗：冒充学校资助中心、教育局或'财政局'，以'助学金/奖学金/困难补贴即将发放，需先激活账户或缴纳手续费'为由，诱导学生点击仿冒统一身份认证页面并填写账号密码、银行卡与短信验证码。校园语境识别点：发放季(9-11月)高发；文案含'逾期视为放弃''需先缴费激活'；发件域多为仿冒校方域。真实流程中校方发放助学金不会要求学生先行转账或缴费。",
     {"domain": "campus_antifraud", "id": "PX-002", "category": "scam-type", "role": "detect", "keywords": ["助学金", "奖学金", "补贴", "教育局", "资助", "发放", "激活", "手续费"], "severity_hint": "high"}),
    ("注销校园贷 / 校园贷诈骗：以'你在校期间注册过校园贷，不注销将影响征信/就业'为由，要求按指引转账'清账'或在多个贷款平台借款后转入指定账户。校园语境识别点：话术含'征信''不良记录''银保监'；施压话术为'限时''会影响考公考研'。正规征信异议处理不会要求先转账。",
     {"domain": "campus_antifraud", "id": "PX-003", "category": "scam-type", "role": "detect", "keywords": ["校园贷", "注销", "征信", "不良记录", "贷款", "清账"], "severity_hint": "high"}),
    ("冒充客服 / 快递退款诈骗：冒充电商或快递客服致电/发信称订单异常需退款，诱导开启屏幕共享或提供银行卡信息，进而盗刷。校园语境识别点：涉及学生网购/快递；话术含'理赔''账户异常''共享屏幕协助操作'。正规平台退款原路返回，不要求共享屏幕或提供验证码。",
     {"domain": "campus_antifraud", "id": "PX-004", "category": "scam-type", "role": "detect", "keywords": ["客服", "退款", "订单异常", "快递", "屏幕共享", "理赔"], "severity_hint": "high"}),
    ("冒充领导/老师/辅导员（含'校长紧急通知'）：通过邮件/QQ/微信冒充校领导、老师或辅导员，以'紧急通知''临时用钱''帮垫付'为由要求转账、扫码或购买礼品卡，常搭配伪造的公文/会议通知。校园语境识别点：显示名为真实职务但发件域异常；要求'不要打电话核实''事后再补手续'；索取金额为便于确认的整数。本次演示样本即'冒充校长紧急通知'。",
     {"domain": "campus_antifraud", "id": "PX-005", "category": "scam-type", "role": "detect", "keywords": ["冒充", "领导", "老师", "辅导员", "校长", "紧急通知", "转账", "扫码", "垫付"], "severity_hint": "high"}),
    ("AI 换脸 / 拟声诈骗（冒充亲友与领导）：利用 AI 换脸或语音克隆在短视频通话/语音中冒充亲友、领导借款。校园语境识别点：通话画质异常、嘴型与语音轻微不同步、拒绝实时互动提问；借钱理由紧急且要求快速转账。判定建议：单一音视频证据不足时降级为'待人工研判'，需线下二次核实渠道。",
     {"domain": "campus_antifraud", "id": "PX-006", "category": "scam-type", "role": "detect", "keywords": ["AI换脸", "拟声", "语音克隆", "视频", "亲友", "冒充", "借钱"], "severity_hint": "medium"}),
    ("仿冒统一身份认证 / 教务 / OA 登录页：搭建与校方统一身份认证、教务系统、OA 高度相似的登录页（常托管在仿冒域名上），收集账号密码与验证码，用于账号接管与横向登录。识别点：页面域名非校方域；表单提交指向外部地址；页面无校方备案信息或安全标识；后续伴随异地登录与批量发信。本项与'账号失陷检测''跨源关联'直接衔接。",
     {"domain": "campus_antifraud", "id": "PX-007", "category": "campaign", "role": "detect", "keywords": ["统一身份认证", "教务", "OA", "登录页", "仿冒", "钓鱼页面", "账号接管"], "severity_hint": "high"}),
    ("涉诈 App 与陌生二维码/安装包诱导：以'发助学金需下载 App''报名需扫码'为由诱导安装来源不明的安装包（APK/免安装 exe），造成账号与资金风险。识别点：下载链接非应用商店；安装包域名与校方无关；要求开启未知来源安装权限或输入账号密码。",
     {"domain": "campus_antifraud", "id": "PX-008", "category": "campaign", "role": "detect", "keywords": ["涉诈App", "安装包", "APK", "二维码", "下载", "未知来源"], "severity_hint": "high"}),
    ("仿冒校园域名命名套路（形近字/同音/连字符/拼音缩写）：仿冒校方域名常见四类套法：①形近字替换（rn→m、1→l、0→o、vv→w）；②同音/拼音与缩写（校名拼音、英文缩写）；③加连字符与冗余词（校名-edu、校名-official、校名-portal）；④把校名嵌在注册域之外（真正注册域非校方所有）。判定要点始终是'**真实注册域归属**'，而非显示文本。示例（合成）：xynu-edu[.]top。",
     {"domain": "campus_antifraud", "id": "PX-009", "category": "domain-pattern", "role": "detect", "keywords": ["仿冒域名", "形近", "同音", "连字符", "拼音", "缩写", "注册域归属"], "severity_hint": "high"}),
    ("可疑 / 廉价顶级域（TLD）集合：钓鱼与诈骗站点大量使用低成本、宽松注册的 TLD：.top .xyz .club .buzz .icu .online .live .click .link .cn.com 等；校方及其服务极少使用此类 TLD。注意：**单独命中 TLD 只作加权信号，不单独定罪**（正常站点也可能用），需与仿冒命名、页面仿冒、IOC 关联共同支撑。",
     {"domain": "campus_antifraud", "id": "PX-010", "category": "domain-pattern", "role": "detect", "keywords": ["TLD", "顶级域", "top", "xyz", "club", "buzz", "icu", "online", "加权信号"], "severity_hint": "medium"}),
    ("子域与后缀仿冒（edu.xxx.com / x.edu.cn.attacker.com）：把校方域名或教育后缀嵌入自己的注册域，制造'看起来像官方'的错觉：①`edu.<attacker>.com`、`mail.<attacker>.net`；②`<校名>.edu.cn.<attacker>.com`（真正注册域是最后一段）。判定规则：**取最右可注册域（eTLD+1）判定归属**，左侧出现的 edu.cn、校名一律视为伪装。",
     {"domain": "campus_antifraud", "id": "PX-011", "category": "domain-pattern", "role": "detect", "keywords": ["子域", "后缀仿冒", "edu.cn", "eTLD+1", "真实注册域", "伪装"], "severity_hint": "high"}),
    ("邮件头异常（Return-Path ≠ From、显示名伪装、SPF/DKIM 失败）：钓鱼邮件的常见头字段异常：①Return-Path/信封发件人与 From 显示发件人不一致；②From 显示名为真实职务（'校长办公室'）但实际地址为外部域；③SPF 为 softfail/fail 或 DKIM 校验失败；④Reply-To 指向与 From 不同的域（便于收信）。判定：任一异常为加权信号，与仿冒域/可疑 URL 同时命中方可高置信定罪。",
     {"domain": "campus_antifraud", "id": "PX-012", "category": "email-header", "role": "detect", "keywords": ["Return-Path", "From", "显示名", "Reply-To", "SPF", "DKIM", "softfail", "fail"], "severity_hint": "high"}),
    ("URL 缩短器与多跳跳转链：正文链接使用短链（t.cn、bit.ly、dwz、suo.im 等）或经多次 302 跳转后落到仿冒页面，用于规避文本特征与人工核对。识别点：短链 + 目标域为可疑 TLD/仿冒命名；跳转链中出现多个中间域。建议：解析到最终落地域后再做归属与页面仿冒判定；无法解析时降级'待人工研判'。",
     {"domain": "campus_antifraud", "id": "PX-013", "category": "email-header", "role": "detect", "keywords": ["短链", "缩短器", "t.cn", "bit.ly", "跳转链", "302", "落地域"], "severity_hint": "medium"}),
    ("高风险附件（.eml/.zip/.docm/.hta/双扩展名）：高风险附件类型：可执行与脚本类（.exe .scr .js .vbs .hta .lnk）、含宏办公文档（.docm .xlsm）、压缩包（.zip .rar 常用于绕过扫描）、以及双扩展名伪装（如`成绩单.pdf.exe`、`通知.doc.js`）。识别点：附件名诱导（'助学金名单''学生信息'）+ 高风险扩展名 + 发件域异常，三者同时命中时判定高风险。安全处置：演示环境只做 hash 记录与静态特征比对，**不执行附件**。",
     {"domain": "campus_antifraud", "id": "PX-014", "category": "email-header", "role": "detect", "keywords": ["附件", "exe", "hta", "docm", "xlsm", "zip", "双扩展名", "宏", "不执行"], "severity_hint": "high"}),
    ("校内真实域名白名单（须由网络中心提供，勿臆造）：用于抑制误报的校方真实域名清单（含校级门户、统一身份认证、教务、OA、邮件、图书馆等）。**本条目为占位：真实域名必须由学校网络中心/信息化部门提供并确认后再填入，严禁臆造或猜测**。命中白名单域的邮件/链接视为可信来源，但若白名单域被仿冒（形近/子域伪装）仍按 PX-009/PX-011 判定。",
     {"domain": "campus_antifraud", "id": "PX-021", "category": "whitelist", "role": "suppress", "keywords": ["白名单", "校内域名", "真实域名", "网络中心确认", "抑制误报"], "severity_hint": "low"}),
    ("邮件网关合法发信路径（SPF/DKIM 通过且来自校内出口）：校方邮件网关/通知系统的合法群发特征：SPF 通过、DKIM 通过、发件服务器在校内出口 IP 段、From 与 Return-Path 同域且为校方域、正文为标准通知模板（选课通知、缴费提醒、会议通知）。用于抑制'批量发信'被直接判为失陷：**批量发信若无账号异常登录伴随，按正常群发处理**；有异常登录伴随才升级为账号失陷。",
     {"domain": "campus_antifraud", "id": "PX-022", "category": "whitelist", "role": "suppress", "keywords": ["邮件网关", "SPF通过", "DKIM通过", "合法发信", "群发通知", "批量发信", "抑制误报"], "severity_hint": "low"}),
    ("选课 / 迎新 / 毕业季高并发基线（≠ 爆破 / DDoS）：选课开放、迎新注册、毕业季集中登录会在短时间产生大量登录请求与失败重试，属**业务高峰基线**，不应判为爆破或 DDoS。识别点：时间窗口与教务公告一致；来源集中在校内网段或校方 CDN；失败模式为'密码错误'而非高频撞库字典特征；同一时段教务系统本身可访问。判定建议：基线窗口内的高并发降权，只有叠加异常来源（境外/代理池）或账号批量失陷证据才升级。",
     {"domain": "campus_antifraud", "id": "PX-023", "category": "baseline", "role": "suppress", "keywords": ["选课", "迎新", "毕业季", "高并发", "业务基线", "降权", "误报抑制"], "severity_hint": "low"}),
    ("合法营销 / 社团活动 / 订阅类邮件：学生会、社团、就业中心、图书馆等的活动通知与订阅邮件常含'报名''链接''二维码''附件'等与钓鱼相似的关键词，但发件域为校方域或已备案第三方平台（如问卷/表单服务）、SPF/DKIM 通过、模板固定。用于抑制基于关键词的浅层误报：**关键词命中只是信号，域名归属与头字段校验才是判据**。",
     {"domain": "campus_antifraud", "id": "PX-024", "category": "whitelist", "role": "suppress", "keywords": ["社团", "活动通知", "营销", "订阅", "问卷", "关键词误报", "抑制"], "severity_hint": "low"}),
    ("校园出口 IP 段与正常外发行为：校内出口 IP 段（由网络中心提供）内的主机常规外发（邮件、DNS、Web）属正常行为；**来自校内出口的攻击面请求多为扫描/合规检测/资产盘点**，不应直接判为外部攻击。异常判据是'校内主机向大量外部目标发起非常规端口连接'或'登录后异常批量行为'。本条目与 PX-026 配合使用；出口 IP 段待校方确认后填入。",
     {"domain": "campus_antifraud", "id": "PX-025", "category": "baseline", "role": "suppress", "keywords": ["出口IP", "校内网段", "正常外发", "扫描", "资产盘点", "待校方确认"], "severity_hint": "low"}),
    ("爬虫 / 合规扫描 ≠ 攻击（沿用既有误报规则）：沿用知识库既有口径：搜索引擎爬虫、校内自查扫描、CDN 健康检查产生的规律性、低危害请求**不等于攻击**。识别点：UA 与来源可识别、请求路径限于公开页面、速率平稳、无漏洞利用特征。判定建议：与'高频+集中+利用特征'区分；不确定时降级'待人工研判'而非直接定罪。",
     {"domain": "campus_antifraud", "id": "PX-026", "category": "baseline", "role": "suppress", "keywords": ["爬虫", "扫描", "≠攻击", "误报", "UA", "合规检测"], "severity_hint": "low"}),
    ("判定原则：单个 IOC 不足以定罪，须跨源关联：单纯命中一个可疑域名/IP/hash 不足以判定真实威胁——必须跨源关联确认'是否产生受害行为'：邮件 IOC 需与 CAS/VPN 登录日志、邮件网关外发日志、WAF 拦截日志交叉，回答'谁访问了、谁登录了、影响面多大'。产出结论须附证据链（邮件头证据 + IOC 清单 + 受害账号清单 + 时间线）。本原则是平台区别于'单点杀毒/黑名单'的核心卖点。",
     {"domain": "campus_antifraud", "id": "PX-031", "category": "verdict-policy", "role": "policy", "keywords": ["单IOC", "跨源关联", "证据链", "受害面", "定罪", "时间线"], "severity_hint": "medium"}),
    ("置信度分级与'待人工研判'降级口径：研判结论分三档：①高置信（≥0.7 且多信号一致，如仿冒域+页面仿冒+SPF失败+跨源受害）→ 可转 TIR 处置审批；②中/低置信 → 标注'待人工研判'，不自动处置；③证据不足或字段对不上（如 account_id 缺失/格式不一致）→ **不猜测、不模糊匹配**，直接降级'待人工研判'（宁可漏，不可让误报刷屏）。所有处置动作一律经人工审批。",
     {"domain": "campus_antifraud", "id": "PX-032", "category": "verdict-policy", "role": "policy", "keywords": ["置信度", "分级", "待人工研判", "降级", "不猜测", "人工审批", "宁可漏"], "severity_hint": "medium"}),
    ("能力边界：不做电话/短信检测，只做涉诈网址/App 研判：诈骗电话/短信发生在运营商网络，校内平台技术上不可见，**明确划出能力边界**；本平台只承接：涉诈网址/App 研判、举报邮件分析、账号失陷检测、受害面排查与预警聚合。汇报与报告须主动声明该边界，避免被质疑'能力夸大'。",
     {"domain": "campus_antifraud", "id": "PX-033", "category": "verdict-policy", "role": "policy", "keywords": ["边界", "电话", "短信", "运营商", "涉诈网址", "App", "预警聚合", "声明"], "severity_hint": "low"}),

]


def _tokenize(text: str) -> list[str]:
    """粗分词：英文/数字 token + 中文 2-12 字段 + 中文 2 字滑窗（去重）。"""
    tokens: list[str] = []
    text = text or ""
    for m in re.findall(r"[A-Za-z0-9_\-\.:]{2,40}", text):
        t = m.strip().lower()
        if t and t not in tokens:
            tokens.append(t)
    for m in re.findall(r"[\u4e00-\u9fff]{2,12}", text):
        if m not in tokens:
            tokens.append(m)
    # 中文 2 字滑窗，增强短词命中（如 "SQL注入怎么防御" 中的 "注入"）
    for m in re.findall(r"[\u4e00-\u9fff]{2,12}", text):
        for i in range(len(m) - 1):
            bigram = m[i:i + 2]
            if bigram not in tokens:
                tokens.append(bigram)
    return tokens


class SecurityKnowledgeBase:
    """EduShield 安全知识库（M1：内置知识 + 关键词打分检索）。"""

    def __init__(self, persist_dir: str = "./chroma_data", collection_name: str = "edushield_knowledge"):
        self.persist_dir = persist_dir
        self.collection_name = collection_name
        self._items: list[tuple[str, dict]] = list(_DEFAULT_KNOWLEDGE)
        self._lock = threading.Lock()
        self._initialized = True

    def _ensure_initialized(self):
        # 兼容旧调用方：M1 无外部依赖，永远就绪
        self._initialized = True

    def add_knowledge(self, texts: list[str], metadatas: list[dict] | None = None, ids: list[str] | None = None):
        with self._lock:
            for i, t in enumerate(texts):
                meta = (metadatas or [{}] * len(texts))[i]
                self._items.append((t, meta))
        logger.info(f"[RAG] 已写入 {len(texts)} 条知识（内置列表）")

    def search(self, query: str, k: int = 5) -> list[str]:
        return [h["content"] for h in self.search_with_scores(query, k)]

    def search_with_scores(self, query: str, k: int = 5) -> list[dict]:
        """关键词打分检索：query token 与知识文本匹配，命中越多分越高。"""
        query = (query or "").strip()
        if not query:
            return []
        q_tokens = _tokenize(query)
        if not q_tokens:
            return []
        scored: list[tuple[float, str]] = []
        with self._lock:
            items = list(self._items)
        for content, _meta in items:
            low = content.lower()
            hits = sum(1 for t in q_tokens if t in low)
            if hits <= 0:
                continue
            # 标题词（冒号前）命中权重更高
            title = content.split("：")[0].lower()
            title_hits = sum(1 for t in q_tokens if t in title)
            score = hits * 2.0 + title_hits * 1.5
            scored.append((score, content))
        scored.sort(key=lambda x: (-x[0], x[1]))
        return [{"content": c, "score": round(s, 1)} for s, c in scored[: max(1, min(k, 20))]]

    def ensure_seeded(self):
        """M1 知识内置，无需播种；保留接口供启动后台线程调用。"""
        logger.info(f"[RAG] 内置知识就绪（{len(self._items)} 条，关键词检索，无外部依赖）")

    def seed_default_knowledge(self):
        """兼容旧调用：内置知识已就绪。"""
        self.ensure_seeded()


# 全局单例
_kb: Optional[SecurityKnowledgeBase] = None


def get_knowledge_base() -> SecurityKnowledgeBase:
    global _kb
    if _kb is None:
        from config.settings import settings
        _kb = SecurityKnowledgeBase(
            persist_dir=settings.CHROMA_PERSIST_DIR,
            collection_name=settings.CHROMA_COLLECTION_NAME,
        )
    return _kb
