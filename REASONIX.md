# EduShield — Cybersecurity Agent

EduShield 是一个基于 DeepSeek 的 AI 网络安全 agent，专为渗透测试、漏洞评估、取证分析和安全审计设计。集成 12+ 内置安全工具、10 个 CVE 利用技能、7 个安全子技能，以及跨工具证据关联与报告生成系统。

---

## 📦 快速开始

### 1. 环境要求

| 组件 | 版本要求 | 用途 |
|------|---------|------|
| **Go** | ≥ 1.25 | 编译运行 |
| **系统** | Linux / macOS | 运行时（Windows 部分功能受限） |
| **API Key** | DeepSeek / OpenAI | 模型调用 |

### 2. 安装 Go 编译环境

#### Linux (Ubuntu/Debian)
```bash
# 下载 Go 1.26.5
wget https://go.dev/dl/go1.26.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.26.5.linux-amd64.tar.gz

# 配置环境变量（加到 ~/.bashrc 或 ~/.zshrc）
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# 验证
go version  # 应输出 go1.26.5 linux/amd64
```

#### macOS
```bash
brew install go  # Homebrew 会自动安装最新版
go version
```

#### CentOS/RHEL
```bash
wget https://go.dev/dl/go1.26.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.26.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
go version
```

### 3. 编译

```bash
# 进入项目目录
cd reasonix

# 一键编译（纯 Go，无需 CGO，无需任何外部依赖）
make build

# 或手动编译
CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/reasonix ./cmd/reasonix

# 验证编译成功
./bin/reasonix --version
```

编译产物：`bin/reasonix`（单个静态二进制文件，无任何依赖，可直接分发）

### 4. 配置 API Key

```bash
# 方式一：环境变量（推荐）
export DEEPSEEK_API_KEY="sk-your-deepseek-api-key-here"

# 方式二：创建配置文件
cat > ~/.config/reasonix/config.toml << 'EOF'
[provider.default]
model = "deepseek-flash"
api_key_env = "DEEPSEEK_API_KEY"
EOF

# 方式三：项目级配置（放在解压目录下）
cat > reasonix.toml << 'EOF'
[provider.default]
model = "deepseek-flash"
api_key_env = "DEEPSEEK_API_KEY"
EOF
```

支持的其他模型：
```bash
# OpenAI
export OPENAI_API_KEY="sk-..."
export REASONIX_DEFAULT_MODEL="gpt-4o"

# 或修改配置文件
# provider.default.model = "gpt-4o"
# provider.default.api_key_env = "OPENAI_API_KEY"
```

### 5. 运行

```bash
# 直接启动
./bin/reasonix

# 指定模型
./bin/reasonix --model deepseek-flash

# 恢复上次会话
./bin/reasonix -c

# 帮助
./bin/reasonix --help
```

---

## 🏴 核心架构

```
               ┌─────────────────────────────────────┐
               │           Controller                │
               │      CLI / TUI / HTTP 统一入口      │
               └──────────┬──────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
   ┌──────────┐   ┌────────────┐   ┌──────────┐
   │  Agent   │   │  Finding   │   │ Provider │
   │ tool-loop│◄──│  Store     │◄─►│(模型后端) │
   │          │   │ (证据中心)  │   └──────────┘
   └────┬─────┘   └────────────┘
        │
   ┌────┴──────────────────────┐
   │   内置安全工具（12个）     │
   │ + Bash 系统工具（50+种）  │
   │ + MCP 外部扩展            │
   └──────────┬───────────────-┘
              │
         ┌────┴────┐
         │ 外部系统 │
         │nmap/sqlmap│
         │metasploit│
         └─────────┘
```

### 证据管理系统

所有安全工具自动将发现写入中央 `FindingStore`：

```
port_scan ──► FindingStore ──► findings (查询/过滤/关联)
cve_search ──►               ──► report   (报告生成)
http_probe ──►               ──► 跨工具关联
```

---

## 🛠️ 内置安全工具

### 侦察与枚举
| 工具 | 功能 | 示例 |
|------|------|------|
| `port_scan` | TCP 端口扫描 + 服务识别 | `port_scan("8.215.92.252")` |
| `dns_enum` | DNS 记录枚举 | `dns_enum("example.com")` |
| `subdomain_enum` | 子域名爆破 | `subdomain_enum("example.com")` |
| `whois_lookup` | WHOIS 查询 | `whois_lookup("example.com")` |
| `ssl_check` | TLS 证书分析 | `ssl_check("example.com")` |

### Web 安全
| 工具 | 功能 | 示例 |
|------|------|------|
| `http_probe` | HTTP 安全头/Cookie/TLS 检测 | `http_probe("http://target")` |
| `vuln_scan` | Web 漏洞扫描 | `vuln_scan("http://target")` |

### 漏洞研究
| 工具 | 功能 | 示例 |
|------|------|------|
| `cve_search` | CVE 查询（NVD API） | `cve_search("nginx")` |
| `hash_identify` | 哈希类型识别 | `hash_identify("5d41402abc4b2a76b9719d911017c592")` |

### 取证分析
| 工具 | 功能 | 示例 |
|------|------|------|
| `forensic_extract` | 文件取证（hash/strings/IOC） | `forensic_extract("/path/to/file")` |

### 证据管理与报告
| 工具 | 功能 |
|------|------|
| `findings` | 安全发现查询与关联（summary/all/correlations 三种模式） |
| `report` | 安全评估报告生成（Markdown 完整报告 / 摘要模式） |

---

## 📋 内置安全技能

### 安全子技能
| 命令 | 用途 |
|------|------|
| `/pentest` | 渗透测试：侦察 → 枚举 → 漏洞发现 → 利用 → 报告 |
| `/vuln-assessment` | 漏洞评估：资产识别 → CVE 关联 → 风险评分 |
| `/forensics` | 数字取证：文件/日志/时间线分析 |
| `/malware-analysis` | 恶意软件静态分析 |
| `/osint` | 开源情报收集 |
| `/incident-response` | 应急响应 |
| `/security-audit` | 安全审计（OWASP/CIS/NIST） |

### CVE 利用技能
| 技能 | 漏洞 | CVSS |
|------|------|:----:|
| `cve-2018-7600` | Drupalgeddon 2 (Drupal RCE) | 9.8 |
| `cve-2021-44228` | Log4Shell (Apache Log4j RCE) | 10.0 |
| `cve-2018-20062` | ThinkPHP 5 RCE | 9.8 |
| `cve-2022-25845` | Fastjson AutoType Bypass RCE | 9.8 |
| `cve-2022-22965` | Spring4Shell (Spring Framework RCE) | 9.8 |
| `cve-2017-5638` | Struts2 S2-045 RCE | 10.0 |
| `cve-2019-20372` | nginx error_page request smuggling | 8.6 |
| `cve-2014-6271` | Shellshock (Bash CGI RCE) | 9.8 |
| `cve-2024-4367` | PDF.js font parsing JS execution | 9.1 |
| `cve-2014-0160` | Heartbleed (OpenSSL memory leak) | 7.5 |

### CTF 攻击模式
| 技能 | 技术领域 |
|------|---------|
| `ssti-exploit` | SSTI 检测与利用（Jinja2/Twig/FreeMarker/Mako） |
| `deserialization-exploit` | PHP/Python/Java 反序列化利用链 |
| `prototype-pollution` | JS/Node.js 原型链污染 |
| `jwt-attack` | JWT 算法混淆/密钥破解/kid 注入/JWK 欺骗 |
| `ssrf-advanced` | SSRF 云元数据/gopher/FastCGI RCE/绕过 |

---

## 🚀 使用示例

### 渗透测试
```
reasonix
> /pentest 扫描 8.215.92.252
```

### 漏洞评估
```
> /vuln-assessment 检查 http://target.com
```

### 查询发现与生成报告
```
> findings(mode: "correlations")   # 交叉关联（开放端口 + CVE）
> findings(mode: "all")            # 所有发现详情
> report(format: "markdown")       # 生成安全报告
```

### 特定 CVE 检测
```
> /cve-2018-7600 扫描 http://target/drupal
```

---

## 📁 目录结构

```
reasonix/
├── bin/                        # 编译产物
├── cmd/
│   └── reasonix/              # 入口
├── internal/
│   ├── agent/                  # Agent 循环
│   ├── control/                # 传输无关控制器
│   ├── config/                 # 配置加载
│   ├── evidence/               # FindingStore 证据管理
│   ├── environment/            # 环境探测（含 SecurityProbes）
│   ├── provider/               # 模型后端
│   ├── skill/                  # 技能系统
│   └── tool/
│       └── builtin/           # 内置工具
├── REASONIX.md                 # 项目记忆（加载到每个 session）
└── docs/                       # 文档
```

---

## 🔧 配置参考

### 配置文件优先级
1. 命令行参数 `--flag`
2. 项目同级 `reasonix.toml`
3. 全局 `~/.config/reasonix/config.toml`
4. 内置默认值

### API Key 配置
```bash
# DeepSeek（默认）
export DEEPSEEK_API_KEY="sk-..."

# OpenAI
export OPENAI_API_KEY="sk-..."

# Anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
```

### 安全提示
- API Key 通过环境变量传入，不会写入配置文件
- 会话文件保存在 `~/.reasonix/sessions/`
- 使用 `--continue` / `-c` 恢复上次会话
- 敏感目标扫描建议在隔离环境中运行

---

## 🛡️ 安全伦理

- 仅测试获得明确书面授权的目标
- 遵循负责任的漏洞披露原则
- 最小化影响，未经明确授权不进行 DoS 或暴力破解
- 不得在会话之外泄露漏洞数据
- 遵守数据隐私法律和计算机欺诈法规

---

## 📝 常见问题

**Q: 编译报错 `go: go.mod requires go 1.25`**
A: Go 版本太低。参考上面安装 Go 1.26.5。

**Q: 启动后提示 API Key 未配置**
A: `export DEEPSEEK_API_KEY="sk-..."` 后再启动。

**Q: 如何在 Windows 上运行？**
A: 大部分工具可以在 Windows 上编译运行，但 Bash 工具和部分系统调用可能受限。建议使用 WSL2 或 Docker。

**Q: 如何自定义模型？**
A: 设置环境变量 `REASONIX_DEFAULT_MODEL="gpt-4o"` 或在 `reasonix.toml` 中配置 `[provider.default]`。

**Q: 会话保存在哪里？**
A: `~/.reasonix/sessions/`。使用 `./reasonix -c` 恢复最近一次会话。
