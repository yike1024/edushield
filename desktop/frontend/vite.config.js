import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { execSync } from "node:child_process";
import { mkdir, readFile, readdir, rename, stat, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";
const devPort = Number(process.env.REASONIX_DESKTOP_VITE_PORT || "5173");
const configDir = dirname(fileURLToPath(import.meta.url));
// Stamps the build commit into the bundle so a minified crash stack can be mapped
// back to the sourcemap of the exact build. Falls back to "dev" off a git checkout.
function buildCommit() {
    if (process.env.REASONIX_COMMIT)
        return process.env.REASONIX_COMMIT;
    try {
        return execSync("git rev-parse --short HEAD", { cwd: configDir }).toString().trim();
    }
    catch {
        return "dev";
    }
}
function buildChannel() {
    return process.env.REASONIX_CHANNEL || "stable";
}
// On macOS ≤ 12 (Safari 15 WebKit) a crossorigin module/stylesheet fetched over the
// wails:// scheme is CORS-blocked (no Access-Control-Allow-Origin from the handler),
// so the bundle never loads and the window paints blank; newer WebKit tolerates it.
function stripCrossorigin() {
    return {
        name: "strip-crossorigin",
        enforce: "post",
        transformIndexHtml: (html) => html.replace(/\s+crossorigin(?==["']|[\s/>])/g, ""),
    };
}
function archiveHiddenSourcemaps(commit) {
    async function collectMapFiles(dir) {
        const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
        const files = [];
        for (const entry of entries) {
            const p = resolve(dir, entry.name);
            if (entry.isDirectory())
                files.push(...(await collectMapFiles(p)));
            else if (entry.isFile() && entry.name.endsWith(".map"))
                files.push(p);
        }
        return files;
    }
    return {
        name: "archive-hidden-sourcemaps",
        apply: "build",
        closeBundle: async () => {
            const distDir = resolve(configDir, "dist");
            const maps = await collectMapFiles(distDir);
            if (!maps.length)
                return;
            const archiveDir = resolve(configDir, "sourcemaps", commit);
            await mkdir(archiveDir, { recursive: true });
            await Promise.all(maps.map(async (mapPath) => {
                const rel = mapPath.slice(distDir.length + 1).replace(/[\\/]+/g, "__");
                await rename(mapPath, resolve(archiveDir, rel));
            }));
            await writeFile(resolve(archiveDir, "manifest.json"), JSON.stringify({ commit, channel: buildChannel(), archivedAt: new Date().toISOString() }, null, 2) + "\n");
        },
    };
}
// Vite must empty dist before production builds so stale hashed assets disappear.
// Recreate the tracked placeholder afterwards so git status stays clean and
// Go's //go:embed all:frontend/dist still works on a fresh checkout.
function keepDistPlaceholder() {
    return {
        name: "keep-dist-placeholder",
        apply: "build",
        closeBundle: async () => {
            const distDir = resolve(configDir, "dist");
            await mkdir(distDir, { recursive: true });
            await writeFile(resolve(distDir, ".gitkeep"), "\n");
        },
    };
}
// Dev-only middleware that serves files from the workspace root (project root)
// so the browser can read @-referenced local files. Without this, Vite's SPA
// fallback returns index.html for any unknown path, so fetch("/SECURITY.md")
// would silently serve the HTML shell instead of the real markdown body.
// Endpoint: GET /__workspace_file__?path=<relative-or-absolute-path>
function workspaceFileServer() {
    // Workspace root = two levels up from desktop/frontend/ (the config dir).
    const workspaceRoot = resolve(configDir, "..", "..");
    const MAX_BYTES = 2_000_000; // 2 MB cap to avoid streaming huge binaries
    // eslint-disable-next-line no-console
    console.log("[workspaceFileServer] workspaceRoot =", workspaceRoot);
    return {
        name: "workspace-file-server",
        apply: "serve",
        configureServer(server) {
            server.middlewares.use(async (req, res, next) => {
                const url = req.url ?? "";
                if (!url.startsWith("/__workspace_file__"))
                    return next();
                try {
                    const parsed = new URL(url, "http://localhost");
                    const rawPath = parsed.searchParams.get("path");
                    if (!rawPath) {
                        res.statusCode = 400;
                        res.end("missing 'path' query param");
                        return;
                    }
                    // eslint-disable-next-line no-console
                    console.log("[workspaceFileServer] request rawPath =", rawPath);
                    // Resolve relative to workspace root; allow absolute paths too.
                    const target = isAbsolute(rawPath)
                        ? normalize(rawPath)
                        : resolve(workspaceRoot, rawPath);
                    // eslint-disable-next-line no-console
                    console.log("[workspaceFileServer] resolved target =", target);
                    // Guard against path traversal escaping the workspace root.
                    const rel = normalize(target);
                    if (!rel.startsWith(normalize(workspaceRoot)) && !isAbsolute(rawPath)) {
                        res.statusCode = 403;
                        res.end("path outside workspace root");
                        return;
                    }
                    const info = await stat(target).catch((e) => {
                        // eslint-disable-next-line no-console
                        console.warn("[workspaceFileServer] stat failed for", target, e?.message);
                        return null;
                    });
                    if (!info || !info.isFile()) {
                        res.statusCode = 404;
                        res.end("file not found");
                        return;
                    }
                    if (info.size > MAX_BYTES) {
                        res.statusCode = 413;
                        res.end(`file too large (${info.size} bytes, max ${MAX_BYTES})`);
                        return;
                    }
                    const buf = await readFile(target);
                    // Best-effort content type by extension.
                    const ext = target.split(".").pop()?.toLowerCase() ?? "";
                    const ct = {
                        md: "text/markdown; charset=utf-8",
                        markdown: "text/markdown; charset=utf-8",
                        txt: "text/plain; charset=utf-8",
                        json: "application/json; charset=utf-8",
                        yaml: "text/yaml; charset=utf-8",
                        yml: "text/yaml; charset=utf-8",
                        ts: "text/typescript; charset=utf-8",
                        tsx: "text/typescript; charset=utf-8",
                        js: "text/javascript; charset=utf-8",
                        jsx: "text/javascript; charset=utf-8",
                        py: "text/x-python; charset=utf-8",
                        go: "text/x-go; charset=utf-8",
                        rs: "text/rust; charset=utf-8",
                        java: "text/x-java; charset=utf-8",
                        c: "text/x-c; charset=utf-8",
                        cpp: "text/x-c++; charset=utf-8",
                        h: "text/x-c; charset=utf-8",
                        sh: "text/x-shellscript; charset=utf-8",
                        bash: "text/x-shellscript; charset=utf-8",
                        sql: "application/sql; charset=utf-8",
                        html: "text/html; charset=utf-8",
                        css: "text/css; charset=utf-8",
                        xml: "application/xml; charset=utf-8",
                        csv: "text/csv; charset=utf-8",
                        toml: "application/toml; charset=utf-8",
                        ini: "text/plain; charset=utf-8",
                        conf: "text/plain; charset=utf-8",
                    }[ext] ?? "application/octet-stream";
                    res.setHeader("Content-Type", ct);
                    res.setHeader("Cache-Control", "no-store");
                    res.statusCode = 200;
                    res.end(buf);
                }
                catch (err) {
                    // eslint-disable-next-line no-console
                    console.error("[workspaceFileServer] handler error:", err);
                    res.statusCode = 500;
                    res.end(`workspace file server error: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
                }
            });
        },
    };
}
const commit = buildCommit();
const channel = buildChannel();
const nodeModulePath = String.raw `[\\/]node_modules[\\/](?:\.pnpm[\\/][^\\/]+[\\/]node_modules[\\/])?`;
const vendorReact = new RegExp(`${nodeModulePath}(?:react|react-dom)(?:[\\/]|$)`);
const vendorMarkdown = new RegExp(`${nodeModulePath}(?:react-markdown|remark-gfm|remark-math|rehype-katex|katex)(?:[\\/]|$)`);
const vendorHighlight = new RegExp(`${nodeModulePath}highlight\\.js(?:[\\/]|$)`);
// base: "./" so built asset URLs are relative. Wails serves the embedded dist from
// the app root over the wails:// scheme, where absolute "/assets/..." URLs 404.
export default defineConfig({
    // errorRecovery tells lightningcss to skip unparseable rules instead of
    // failing the whole build. Vite 8 + lightningcss 1.32.0 can reject valid
    // @keyframes in concatenated CSS bundles (heartbeat.css + styles.css).
    css: {
        lightningcss: { errorRecovery: true },
    },
    plugins: [react(), stripCrossorigin(), archiveHiddenSourcemaps(commit), keepDistPlaceholder(), workspaceFileServer()],
    base: "./",
    define: { __BUILD_COMMIT__: JSON.stringify(commit), __BUILD_CHANNEL__: JSON.stringify(channel) },
    build: {
        outDir: "dist",
        emptyOutDir: true,
        sourcemap: "hidden",
        target: "es2021",
        // Use terser for smaller output (esbuild is faster to build but produces
        // larger bundles). Disabled for dev builds via the default.
        minify: "terser",
        terserOptions: {
            compress: {
                // Keep warn/error so crash breadcrumbs still capture them; drop the noise.
                drop_console: ["log", "debug", "info", "trace"],
                passes: 2,
            },
            // Preserve names so minified crash stacks stay readable.
            keep_classnames: true,
            keep_fnames: true,
        },
        rolldownOptions: {
            output: {
                // Manual chunk splitting: keep the heavy markdown/math/code pipeline
                // in a separate chunk so it can be cached independently from the
                // app shell. The vendor chunk splits react+react-dom (stable, rarely
                // changes) from the markdown stack (changes more often).
                codeSplitting: {
                    groups: [
                        { name: "vendor-react", test: vendorReact },
                        { name: "vendor-markdown", test: vendorMarkdown },
                        { name: "vendor-highlight", test: vendorHighlight },
                    ],
                },
            },
        },
        // Raise the warning limit — the markdown vendor chunk is legitimately large
        // (katex alone is ~300KB). The manual split ensures it's cached separately.
        chunkSizeWarningLimit: 600,
    },
    server: {
        // Bind IPv4 — unset host listens on ::1, and the Wails dev proxy's [::1]
        // dial fails on Windows hosts where IPv6 loopback is filtered.
        host: "127.0.0.1",
        port: devPort,
        strictPort: true,
        proxy: {
            "/deepseek-api": {
                target: "https://api.deepseek.com",
                changeOrigin: true,
                rewrite: (path) => path.replace(/^\/deepseek-api/, ""),
                // deepseek-v4-flash is a reasoning model — complex prompts can take
                // 60s+ to return. The default proxy timeout is too short and surfaces
                // as a 502 Bad Gateway before DeepSeek finishes thinking.
                timeout: 300_000, // 5 min — socket idle timeout
                proxyTimeout: 300_000, // 5 min — upstream response timeout
            },
            // AiSOC Brain API proxy (5 domains unified to brain port 6657)
            // 主代理用大脑侧部件名 intel；threatintel 保留做兼容（已弃用）
            "/aisoc-brain": {
                target: "http://127.0.0.1:6657",
                changeOrigin: true,
                rewrite: (path) => path.replace(/^\/aisoc-brain/, ""),
                timeout: 600_000,
                proxyTimeout: 600_000,
                // EventSource (SSE) 必须关闭代理缓冲并透传所需头，否则前端等不到首字节就超时
                ws: true,
                headers: {
                    "Accept": "text/event-stream",
                    "Cache-Control": "no-cache",
                    Connection: "keep-alive",
                },
                configure: (proxy) => {
                    proxy.on("proxyReq", (proxyReq, req) => {
                        // 防止 http-proxy 对 SSE 默认加 Content-Length / 缓冲
                        if (req.headers.accept?.includes("text/event-stream")) {
                            proxyReq.removeHeader("content-length");
                        }
                    });
                    proxy.on("proxyRes", (proxyRes, req, res) => {
                        if (req.headers.accept?.includes("text/event-stream") || proxyRes.headers["content-type"]?.includes("text/event-stream")) {
                            // SSE 必须禁用压缩/缓冲
                            proxyRes.headers["cache-control"] = "no-cache, no-transform";
                            proxyRes.headers["connection"] = "keep-alive";
                            proxyRes.headers["x-accel-buffering"] = "no";
                            res.flushHeaders?.();
                        }
                    });
                },
            },
            "/aisoc-pentest": {
                target: "http://127.0.0.1:6657",
                changeOrigin: true,
                rewrite: (path) => path.replace(/^\/aisoc-pentest/, ""),
                timeout: 600_000,
                proxyTimeout: 600_000,
                ws: true,
            },
            "/aisoc-logaudit": {
                target: "http://127.0.0.1:6657",
                changeOrigin: true,
                rewrite: (path) => path.replace(/^\/aisoc-logaudit/, ""),
                timeout: 600_000,
                proxyTimeout: 600_000,
                ws: true,
            },
            "/aisoc-intel": {
                target: "http://127.0.0.1:6657",
                changeOrigin: true,
                rewrite: (path) => path.replace(/^\/aisoc-intel/, ""),
                timeout: 600_000,
                proxyTimeout: 600_000,
                ws: true,
            },
            "/aisoc-threatintel": {
                target: "http://127.0.0.1:6657",
                changeOrigin: true,
                rewrite: (path) => path.replace(/^\/aisoc-threatintel/, ""),
                timeout: 600_000,
                proxyTimeout: 600_000,
                ws: true,
            },
            "/aisoc-incident": {
                target: "http://127.0.0.1:6657",
                changeOrigin: true,
                rewrite: (path) => path.replace(/^\/aisoc-incident/, ""),
                timeout: 600_000,
                proxyTimeout: 600_000,
                ws: true,
            },
        },
    },
});
