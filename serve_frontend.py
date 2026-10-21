#!/usr/bin/env python3
"""EduShield 前端代理服务器
- 静态文件服务 (dist/)
- /aisoc-brain/api/* → aisoc-brain (port 6657) /api/*
- /aisoc-pentest/api/* → aisoc-brain (port 6657) /api/*
- /aisoc-logaudit/api/* → aisoc-brain (port 6657) /api/*
- /aisoc-intel/api/* → aisoc-brain (port 6657) /api/*     (主，威胁情报部件名)
- /aisoc-threatintel/api/* → aisoc-brain (port 6657) /api/* (兼容别名)
- /aisoc-incident/api/* → aisoc-brain (port 6657) /api/*
- /api/* → aisoc-brain (port 6657)
"""
import http.server
import urllib.request
import http.client
import os
import sys

PORT = 3000
DIST_DIR = os.path.join(os.path.dirname(__file__), "desktop", "frontend", "dist")

# 路由映射: 前缀 → (目标地址, 是否去除前缀)
# 去除前缀时，目标地址需包含替换后的路径前缀
# 注：威胁情报部件大脑侧名为 'intel'。/aisoc-intel/api 为主路由，
# /aisoc-threatintel/api 保留做兼容（与前端 aisoc-api.ts / vite.config.ts 对齐）。
ROUTES = [
    ("/aisoc-brain/api",         "http://127.0.0.1:6657/api",  True),
    ("/aisoc-pentest/api",       "http://127.0.0.1:6657/api",  True),
    ("/aisoc-logaudit/api",      "http://127.0.0.1:6657/api",  True),
    ("/aisoc-intel/api",         "http://127.0.0.1:6657/api",  True),
    ("/aisoc-threatintel/api",   "http://127.0.0.1:6657/api",  True),  # 兼容别名
    ("/aisoc-incident/api",      "http://127.0.0.1:6657/api",  True),
    # 部件 adapter 事件流直连（大脑转发工具帧时丢弃了 args/output，需从 adapter 原始流补全）
    # 目标用 /api/events 前缀，adapter 对 /api/* 免认证
    ("/adapter-pentest/events",  "http://127.0.0.1:8786/api/events",  True),
    ("/adapter-logaudit/events", "http://127.0.0.1:8788/api/events",  True),
    ("/api",                     "http://127.0.0.1:6657",      False),
]


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    # 修复 Bug【ERR_INVALID_HTTP_RESPONSE 黑屏】：用 HTTP/1.0 而不是 1.1。
    # 原 protocol_version = "HTTP/1.1" 有三个隐藏问题：
    #   1) Python BaseHTTPRequestHandler + HTTP/1.1 默认不会发 Connection: keep-alive/close 头，
    #      写完 body 后也不主动 shutdown socket；Chrome/Edge 对 HTTP/1.1 响应会等待 EOF 或
    #      Connection 头声明，拿到"既无 Connection 头又无 EOF"的响应会抛 net::ERR_INVALID_HTTP_RESPONSE，
    #      <script type="module"> 加载失败 → #root 真空 → 黑屏。
    #   2) HTTP/1.1 + 没 ETag/Last-Modified/Cache-Control 的静态文件响应会让浏览器按启发式缓存，
    #      第二次访问拿陈旧 chunk 仍然会复现黑屏。
    #   3) HTTP/1.1 默认 keep-alive，静态文件服务不需要复用连接，反而增加 socket 泄漏风险。
    # 改用 HTTP/1.0 后响应结束服务端主动关闭 socket，Chrome/Edge 都能正常解析。
    protocol_version = "HTTP/1.0"
    timeout = 300  # SSE 长连接超时

    def _match_route(self):
        for prefix, target, strip in ROUTES:
            if self.path.startswith(prefix + "/") or self.path == prefix:
                remaining = self.path[len(prefix):] if strip else self.path
                return target + remaining
        return None

    def do_GET(self):
        target = self._match_route()
        if target:
            self._proxy(target)
        else:
            self._serve_static()

    def do_POST(self):
        target = self._match_route()
        if target:
            self._proxy(target, method="POST")
        else:
            self._serve_static()

    # HTTP/1.0 静态文件需要 HEAD 支持（preload/prefetch 会发 HEAD 探测）。
    # 之前 do_HEAD 缺失，preload link rel="modulepreload" 收到 501 Method Not Implemented
    # → 默默 preload 失败但不影响主 bundle；为完整性补上。
    def do_HEAD(self):
        target = self._match_route()
        if target:
            self._proxy(target, method="HEAD")
        else:
            self._serve_static(head_only=True)

    def _proxy(self, target_url, method="GET"):
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            host = parsed.hostname
            port = parsed.port or 80
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length > 0 else None

            # 修复 502：上游 HTTPConnection 原本 timeout=60，brain 长任务经常超过 60s 没字节，
            # resp.read1 抛超时 → 代理 raise → 浏览器收 502 Bad Gateway，流被腰斩。
            # 改为 3600s（1 小时），与前端 chatStream 空闲 5 分钟 + brain 部件超时一致；
            # 浏览器断流后下次 read1 也会因对端关闭而抛 BrokenPipe/ConnectionReset 正常跳出。
            conn = http.client.HTTPConnection(host, port, timeout=3600)
            headers = {}
            for key, val in self.headers.items():
                if key.lower() not in ("host", "connection"):
                    headers[key] = val
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            content_type = resp.getheader("Content-Type", "")

            # SSE: 流式转发，逐块 flush
            # 修复：上游（DeepSeek / FastAPI SSE）发完 data: [DONE] 后不主动关连接，
            # resp.read1(4096) 会永远阻塞等待下一字节 → 浏览器 fetch reader.read() 不返回 done
            # → 前端 chatStream 不 resolve → submitForTab pending → React submitting 卡死。
            # 这里检测到 [DONE] 标记后立即 break + conn.close()，让浏览器收到 EOF。
            if "text/event-stream" in content_type:
                self.send_response(resp.status)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.send_header("X-Accel-Buffering", "no")
                self.end_headers()
                saw_done = False
                while True:
                    chunk = resp.read1(4096)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
                    if not saw_done and b"[DONE]" in chunk:
                        saw_done = True
                        break
                try:
                    conn.close()
                except Exception:
                    pass
                try:
                    self.wfile.close()
                except Exception:
                    pass
                return

            # 普通请求
            data = resp.read()
            conn.close()
            self.send_response(resp.status)
            for key, val in resp.getheaders():
                if key.lower() not in ("transfer-encoding", "connection", "content-length"):
                    self.send_header(key, val)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"Proxy error: {e}".encode())

    def _serve_static(self, head_only=False):
        path = self.path.split("?")[0].rstrip("/")
        if path == "":
            path = "/index.html"
        file_path = os.path.join(DIST_DIR, path.lstrip("/"))
        content_types = {
            ".html": "text/html", ".js": "application/javascript",
            ".css": "text/css", ".json": "application/json",
            ".svg": "image/svg+xml", ".png": "image/png",
            ".ico": "image/x-icon", ".woff2": "font/woff2",
        }
        if os.path.isfile(file_path):
            ext = os.path.splitext(file_path)[1]
            size = os.path.getsize(file_path)
            self.send_response(200)
            self.send_header("Content-Type", content_types.get(ext, "application/octet-stream"))
            self.send_header("Content-Length", str(size))
            # 防默认 keep-alive 让 Chrome 等不到响应终结报 ERR_INVALID_HTTP_RESPONSE
            self.send_header("Connection", "close")
            self.end_headers()
            if head_only:
                return
            with open(file_path, "rb") as f:
                data = f.read()
            self.wfile.write(data)
        else:
            index_path = os.path.join(DIST_DIR, "index.html")
            if os.path.isfile(index_path):
                with open(index_path, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                if head_only:
                    return
                self.wfile.write(data)
            else:
                self.send_response(404)
                self.send_header("Connection", "close")
                self.end_headers()

    def log_message(self, format, *args):
        if "/api/" in str(args[0]) if args else False:
            print(f"[PROXY] {args[0]}")


if __name__ == "__main__":
    print(f"EduShield Frontend Server")
    print(f"  Static: {DIST_DIR}")
    print(f"  Routes:")
    for prefix, target, strip in ROUTES:
        print(f"    {prefix}/* -> {target} {'(strip prefix)' if strip else ''}")
    print(f"  Listening: http://0.0.0.0:{PORT}")
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), ProxyHandler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
