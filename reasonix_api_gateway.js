#!/usr/bin/env node
/**
 * EduShield API 网关
 *
 * 拓扑：
 *  
 *
 * 两套路由表（参考 frontend-api.md）：
 *   A. 直通端点：/api/status、/api/models、/api/history、/api/sessions、/api/context、/api/submit、/api/approve、/api/cancel
 *   B. 合成端点（reasonix 无独立路由，从 /status 提取）：/api/meta、/api/balance、/api/settings、/api/capabilities
 *   C. SSE 直通：/events → 8791/events
 *   D. 健康检查：/ → 网关状态
 *   E. 未知路径 → JSON 404（非 HTML fallback）
 */
'use strict';

const http = require('http');
const { URL } = require('url');

function parseArgs() {
  const args = { port: 8787, target: 'http://127.0.0.1:8791' };
  for (let i = 2; i < process.argv.length; i++) {
    if (process.argv[i] === '--port' && process.argv[i + 1]) args.port = parseInt(process.argv[i + 1], 10);
    if (process.argv[i] === '--target' && process.argv[i + 1]) args.target = process.argv[i + 1];
  }
  return args;
}

const { port: PORT, target: TARGET } = parseArgs();

// ─── 合成端点缓存（每次 /api/status 刷新） ───
let statusCache = null;
let statusCacheTime = 0;
const CACHE_TTL = 2000; // 2s

async function fetchStatus() {
  const now = Date.now();
  if (statusCache && (now - statusCacheTime) < CACHE_TTL) return statusCache;
  try {
    const data = await proxyFetch('/status');
    statusCache = data;
    statusCacheTime = now;
    return data;
  } catch {
    return statusCache || {};
  }
}

// ─── 通用代理（非流式，用于 JSON 端点） ───
function proxyFetch(path) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, TARGET);
    const req = http.request({
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: 'GET',
      timeout: 10000,
    }, (res) => {
      let body = '';
      res.on('data', (chunk) => body += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch { resolve(body); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.end();
  });
}

// ─── 合成 /api/meta ───
async function handleMeta() {
  const s = await fetchStatus();
  return {
    label: s.label || '',
    ready: s.running !== undefined,
    eventChannel: '',
    cwd: s.cwd || '',
    autoApproveTools: s.autoApproveTools,
    bypass: s.bypass,
    toolApprovalMode: s.toolApprovalMode,
    goal: s.goal,
    goalStatus: s.goalStatus,
  };
}

// ─── 合成 /api/balance ───
async function handleBalance() {
  const s = await fetchStatus();
  return s.balance || { available: false, display: 'N/A' };
}

// ─── 合成 /api/settings ───
async function handleSettings() {
  const s = await fetchStatus();
  return {
    autoApproveTools: s.autoApproveTools || false,
    bypass: s.bypass || false,
    toolApprovalMode: s.toolApprovalMode || 'ask',
    plan: s.plan || false,
    goal: s.goal || '',
    goalStatus: s.goalStatus || 'stopped',
  };
}

// ─── 合成 /api/capabilities ───
function handleCapabilities() {
  return { servers: [], skills: [], skillRoots: [], plugins: [] };
}

// ─── 直通端点（/api/xxx → reasonix /xxx，POST 方法） ───
function proxyToReasonix(path, req) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, TARGET);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: req.method,
      headers: { ...req.headers, host: url.host },
      timeout: 30000,
    };

    const proxy = http.request(options, (proxyRes) => {
      let body = '';
      proxyRes.on('data', (chunk) => body += chunk);
      proxyRes.on('end', () => {
        try { resolve({ status: proxyRes.statusCode, headers: proxyRes.headers, body: JSON.parse(body) }); }
        catch { resolve({ status: proxyRes.statusCode, headers: proxyRes.headers, body }); }
      });
    });
    proxy.on('error', reject);
    proxy.on('timeout', () => { proxy.destroy(); reject(new Error('timeout')); });

    // 转发 POST body
    let body = '';
    req.on('data', (chunk) => body += chunk);
    req.on('end', () => { proxy.end(body || undefined); });
  });
}

// ─── SSE 流转发 ───
function proxySSE(req, res) {
  const url = new URL('/events', TARGET);
  const options = {
    hostname: url.hostname,
    port: url.port,
    path: url.pathname + url.search,
    method: 'GET',
    headers: { ...req.headers, host: url.host },
  };

  const proxy = http.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
    proxyRes.on('error', () => res.end());
  });
  proxy.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
  req.pipe(proxy);
}

// ─── JSON 响应工具 ───
function jsonResponse(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
  });
  res.end(body);
}

// ─── 路由分发 ───
const server = http.createServer(async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') { res.writeHead(200); return res.end(); }

  const url = new URL(req.url, 'http://localhost');
  const path = url.pathname;

  try {
    // D. 健康检查
    if (path === '/') {
      return jsonResponse(res, 200, { status: 'ok', service: 'reasonix-api-gateway', target: TARGET, uptime: process.uptime() });
    }

    // C. SSE 直通（前端 baseUrl 带 /api 前缀，也需匹配 /api/events）
    if (path === '/events' || path === '/api/events') {
      res.setHeader('Access-Control-Allow-Origin', '*');
      return proxySSE(req, res);
    }

    // /api/* 路由
    if (path.startsWith('/api/')) {
      const apiPath = path.slice(5); // /api/status → status

      // B. 合成端点（reasonix 无独立路由，从 /status 提取）
      if (apiPath === 'meta') return jsonResponse(res, 200, await handleMeta());
      if (apiPath === 'balance') return jsonResponse(res, 200, await handleBalance());
      if (apiPath === 'settings') return jsonResponse(res, 200, await handleSettings());
      if (apiPath === 'capabilities') return jsonResponse(res, 200, handleCapabilities());
      // reasonix 无 /health 路由，网关提供规范健康检查端点
      if (apiPath === 'health') return jsonResponse(res, 200, { status: 'ok', service: 'reasonix', version: '1.0' });

      // A. 直通端点：/api/xxx → reasonix /xxx
      const allowed = ['status', 'models', 'history', 'sessions', 'context', 'submit', 'approve', 'cancel'];
      if (allowed.includes(apiPath)) {
        const result = await proxyToReasonix(`/${apiPath}`, req);
        return jsonResponse(res, result.status, result.body);
      }

      // 未知 /api 路径 → JSON 404
      return jsonResponse(res, 404, { error: 'not found', path });
    }

    // E. 未知路径 → JSON 404
    jsonResponse(res, 404, { error: 'not found', path });
  } catch (err) {
    console.error(`[gateway] ${req.method} ${path} error: ${err.message}`);
    if (!res.headersSent) jsonResponse(res, 502, { error: 'bad gateway', detail: err.message, target: TARGET });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[reasonix-api-gateway] listening on 127.0.0.1:${PORT} → ${TARGET}`);
  console.log(`[reasonix-api-gateway] /api/* 直通 + 合成端点(meta/balance/settings/capabilities)已就绪`);
});