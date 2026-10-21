# EduShield Web - VPS 部署指南

## 部署架构

```
[ 用户浏览器 ]                         [ VPS (有 SSH 账号的人都能访问) ]                    [ DeepSeek ]
   │                                          │                                              │
   │ 1. 访问 http://vps-ip/                    │                                              │
   │ ────────────────────────────────────────>│                                              │
   │ 2. 返回 index.html + JS 静态资源           │                                              │
   │ <────────────────────────────────────────│                                              │
   │                                          │                                              │
   │ 3. 用户在设置面板输入自己的 API Key        │                                              │
   │    (浏览器 localStorage 存储，不上传服务器) │                                              │
   │                                          │                                              │
   │ 4. fetch /deepseek-api/v1/chat/completions│                                              │
   │    Header: Authorization: Bearer <用户key>│                                              │
   │ ────────────────────────────────────────>│ 5. Nginx 反代到 https://api.deepseek.com    │
   │                                          │ ────────────────────────────────────────────>│
   │                                          │ <────────────────────────────────────────────│
   │ 6. SSE 流式响应（打字机逐字返回）            │                                              │
   │ <────────────────────────────────────────│                                              │
```

**特点**：
- 服务器侧**不保存任何用户的 API Key**
- 每个 SSH 用户在浏览器里输入自己的 Key，存到自己的 localStorage
- 多用户隔离：A 用户的 Key 不会被 B 用户看到
- DeepSeek API 调用通过 Nginx 反代，绕开浏览器 CORS 限制

---

## 前置条件

- VPS：Ubuntu 20.04+ / Debian 11+ / CentOS 8+（任意 Linux 发行版）
- 已安装 `nginx`（`sudo apt install nginx`）
- 已安装 `node` 18+ 和 `pnpm`（用于本地构建前端）
- 有 sudo 权限（用于修改 nginx 配置 + 重启服务）

---

## 部署步骤

### 第 1 步：本地构建前端

在本地开发机（你的 Windows / WSL）执行：

```bash
cd d:/揭榜挂帅/EduShield-Security/DeepSeek-Reasonix/desktop/frontend

# 安装依赖（如果没装过）
pnpm install

# 生产构建
pnpm build
```

构建产物在 `desktop/frontend/dist/` 目录。

### 第 2 步：上传到 VPS

在你的 VPS 上创建目录：

```bash
ssh user@your-vps-ip
sudo mkdir -p /var/www/reasonix
sudo chown $USER:$USER /var/www/reasonix
```

在本地用 scp / rsync 上传：

```bash
# Windows PowerShell
scp -r d:/揭榜挂帅/EduShield-Security/DeepSeek-Reasonix/desktop/frontend/dist/* user@your-vps-ip:/var/www/reasonix/

# 或用 rsync（推荐，增量上传）
rsync -avz --delete desktop/frontend/dist/ user@your-vps-ip:/var/www/reasonix/
```

### 第 3 步：安装 Nginx 配置

```bash
ssh user@your-vps-ip

# 上传配置文件（从本仓库 deploy/nginx.conf）
sudo cp /path/to/reasonix/deploy/nginx.conf /etc/nginx/sites-available/reasonix
sudo ln -sf /etc/nginx/sites-available/reasonix /etc/nginx/sites-enabled/reasonix

# 删除默认站点（避免端口冲突）
sudo rm -f /etc/nginx/sites-enabled/default

# 测试配置语法
sudo nginx -t

# 重载 Nginx
sudo systemctl reload nginx
```

### 第 4 步：开放防火墙端口

```bash
# Ubuntu / Debian (ufw)
sudo ufw allow 80/tcp
sudo ufw reload

# CentOS / RHEL (firewalld)
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --reload
```

如果是云服务器，还需要在云控制台的安全组里放行 80 端口。

### 第 5 步：验证

浏览器访问 `http://your-vps-ip/`，应该看到 EduShield 界面。

第一次访问时，输入框发送消息会提示"尚未配置 API Key"。点击右上角设置，输入 DeepSeek API Key 即可开始使用。

---

## 可选：启用 HTTPS

强烈建议生产环境启用 HTTPS（避免 API Key 在网络中明文传输）：

```bash
# 安装 certbot
sudo apt install certbot python3-certbot-nginx

# 自动配置 Let's Encrypt 证书
sudo certbot --nginx -d your-domain.com
```

certbot 会自动修改 nginx 配置，把 80 端口重定向到 443，并设置证书自动续期。

---

## 可选：把 80 端口改成其他端口

如果 80 端口被占用，或想用其他端口（例如 8080）：

修改 `deploy/nginx.conf` 的第一行：
```nginx
listen 8080;
```

然后开放对应防火墙端口：
```bash
sudo ufw allow 8080/tcp
```

---

## 多用户使用说明

每个有 SSH 账号的人，都可以通过浏览器访问 `http://your-vps-ip/`：

1. 打开网页
2. 点右上角齿轮 / 设置 → Provider / API Key
3. 粘贴自己的 DeepSeek API Key（获取地址：https://platform.deepseek.com/apiKeys）
4. 选择模型（默认 deepseek-v4-flash，可选 deepseek-chat / deepseek-reasoner 等）
5. 开始对话

每个用户的 API Key 只存在自己浏览器的 localStorage 里，关闭浏览器后下次访问仍然保留（除非清缓存）。

---

## 常见问题

### Q1: 浏览器控制台报 CORS 错误？

检查 Nginx 配置里 `/deepseek-api/` location 是否生效：
```bash
curl -v http://your-vps-ip/deepseek-api/v1/models -H "Authorization: Bearer test"
```
应该看到 DeepSeek 返回的 401（说明反代通了，只是 key 不对）。

### Q2: 发送消息后浏览器一直转圈？

可能是 Nginx 缓冲没关。检查 `nginx.conf` 里有这三行：
```nginx
proxy_buffering off;
proxy_cache off;
proxy_request_buffering off;
```

### Q3: 推理模型响应超过 5 分钟被切断？

修改 `nginx.conf` 的超时配置：
```nginx
proxy_send_timeout 1200s;  # 20 分钟
proxy_read_timeout 1200s;
```
然后 `sudo systemctl reload nginx`。

### Q4: 如何更新前端代码？

本地重新 `pnpm build`，再用 scp/rsync 覆盖 `/var/www/reasonix/` 即可，不需要重启 Nginx。

### Q5: 如何查看 Nginx 访问日志？

```bash
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```
