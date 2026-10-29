/**
 * HTTP API适配器
 * 用于在浏览器环境中连接到reasonix HTTP服务，替代mock数据
 *
 * 当reasonix serve运行时，前端可以通过HTTP API连接到真实服务
 * 而不是使用mock数据
 */

import type {
  HistoryMessage,
  Meta,
  ContextInfo,
  BalanceInfo,
  ModelInfo,
  SettingsView,
  CapabilitiesView,
  SessionMeta,
  WireEvent,
} from './types';

// HTTP API端点配置
// 浏览器模式通过 3000 代理访问 reasonix，相对路径走 serve_frontend.py 路由：
//   /aisoc-pentest/api/* → proxy strip → 8787/* (reasonix 原生无前缀路由)
// Wails 桌面端优先走 Go 绑定，此适配器仅作为 HTTP 降级兜底。
const HTTP_API_BASE_URL = '/aisoc-pentest/api';
const API_TIMEOUT = 30000; // 30秒超时

/**
 * HTTP API客户端类
 * 实现与reasonix HTTP服务的通信
 */
class HttpApiClient {
  private baseUrl: string;
  private authToken: string | null = null;
  private eventSource: EventSource | null = null;

  constructor(baseUrl: string = HTTP_API_BASE_URL) {
    this.baseUrl = baseUrl;
    // 尝试从localStorage获取auth token
    this.authToken = localStorage.getItem('reasonix_auth_token');
  }

  /**
   * 设置认证token
   */
  setAuthToken(token: string): void {
    this.authToken = token;
    localStorage.setItem('reasonix_auth_token', token);
  }

  /**
   * 清除认证token
   */
  clearAuthToken(): void {
    this.authToken = null;
    localStorage.removeItem('reasonix_auth_token');
  }

  /**
   * 通用HTTP请求方法
   */
  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...options.headers as Record<string, string>,
    };

    // 添加认证头
    if (this.authToken) {
      headers['Authorization'] = `Bearer ${this.authToken}`;
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        signal: AbortSignal.timeout(API_TIMEOUT),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP ${response.status}: ${errorText}`);
      }

      // reasonix 的 submit/cancel/approve 返回 202/204 且无 body，
      // response.json() 会抛 "Unexpected end of JSON input"。
      // 改用 text + 判断空体：空体返回 undefined，其余按 JSON 解析。
      const text = await response.text();
      if (!text) return undefined as unknown as T;
      return JSON.parse(text) as T;
    } catch (error) {
      console.error('HTTP API request failed:', error);
      throw error;
    }
  }

  /**
   * 提交用户输入
   */
  async submit(input: string): Promise<void> {
    return this.request('/submit', {
      method: 'POST',
      body: JSON.stringify({ input }),
    });
  }

  /**
   * 取消当前任务
   */
  async cancel(): Promise<void> {
    return this.request('/cancel', {
      method: 'POST',
    });
  }

  /**
   * 批准工具调用
   */
  async approve(id: string, allow: boolean): Promise<void> {
    return this.request('/approve', {
      method: 'POST',
      body: JSON.stringify({ id, allow }),
    });
  }

  /**
   * 获取历史消息
   */
  async history(): Promise<HistoryMessage[]> {
    return this.request<HistoryMessage[]>('/history');
  }

  /**
   * 获取元数据
   */
  async meta(): Promise<Meta> {
    return this.request<Meta>('/meta');
  }

  /**
   * 获取上下文使用情况
   */
  async contextUsage(): Promise<ContextInfo> {
    return this.request<ContextInfo>('/context');
  }

  /**
   * 获取余额信息
   */
  async balance(): Promise<BalanceInfo> {
    return this.request<BalanceInfo>('/balance');
  }

  /**
   * 获取模型信息
   */
  async models(): Promise<ModelInfo[]> {
    return this.request<ModelInfo[]>('/models');
  }

  /**
   * 获取设置
   */
  async settings(): Promise<SettingsView> {
    return this.request<SettingsView>('/settings');
  }

  /**
   * 获取能力信息
   */
  async capabilities(): Promise<CapabilitiesView> {
    return this.request<CapabilitiesView>('/capabilities');
  }

  /**
   * 获取会话列表
   */
  async sessions(): Promise<SessionMeta[]> {
    return this.request<SessionMeta[]>('/sessions');
  }

  /**
   * 连接到事件流
   */
  connectEventStream(onEvent: (event: WireEvent) => void, onError?: (error: Event) => void): EventSource {
    if (this.eventSource) {
      this.eventSource.close();
    }

    const eventUrl = `${this.baseUrl}/events`;
    this.eventSource = new EventSource(eventUrl);

    this.eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        onEvent(data as WireEvent);
      } catch (error) {
        console.error('Failed to parse SSE event:', error);
      }
    };

    if (onError) {
      this.eventSource.onerror = onError;
    }

    return this.eventSource;
  }

  /**
   * 断开事件流
   */
  disconnectEventStream(): void {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
  }

  /**
   * 健康检查
   * reasonix 无 /health 路由，改用 /status（真实存在）判断服务可用性。
   */
  async healthCheck(): Promise<{ status: string; version: string }> {
    return this.request('/status');
  }

  /**
   * 上传非图片附件到大脑并返回相对路径（修复 Bug【web 模式 SavePastedFile 永远返回 undefined】）
   *
   * 与桌面端 Wails 桥（desktop/app.go:9120 → control.SaveAttachmentDataURL）等价；
   * 调用大脑新增的 POST /save-attachment 端点（详见
   * aisoc-docs/13-大脑新增附件上传端点.md），要求 application/json。
   *
   * 参数：
   *   name    - 用户原文件名（含扩展名，如 "access.log"）；服务端会用扩展名
   *             生成安全后缀 [a-z0-9]{1,12}，其他写入 .bin。
   *   dataUrl - "data:<mime>;base64,<...>"，服务端正则只识别 base64 + ; 前缀。
   *
   * 返回：相对路径（如 ".reasonix/attachments/clipboard-...txt"），前端 Web Composer
   *       会把它塞进 attachments Map，后续 expandFileReferences 不会直接读它
   *       （当前架构下，web 附件内容是读 Map 然后 UTF-8 解码内联进消息文本），
   *       但路径要可读以兼容后续 brain→部件协议设计。
   *
   * 上限：服务端 maxFileAttachmentBytes = 25 MB，超出应抛 413。
   *
   * 注意：超时用 60s（其他端点 30s 不够，10 MB base64 ≈ 13.3 MB 文本 + 走 proxy / nginx
   *       + 服务端 base64 解码 + 写盘，可能跑满默认超时）。
   */
  async savePastedFile(name: string, dataUrl: string): Promise<string> {
    const url = `${this.baseUrl}/save-attachment`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (this.authToken) {
      headers['Authorization'] = `Bearer ${this.authToken}`;
    }
    const resp = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({ name, dataUrl }),
      signal: AbortSignal.timeout(60_000),
    });
    if (!resp.ok) {
      const txt = await resp.text();
      throw new Error(`save-attachment HTTP ${resp.status}: ${txt}`);
    }
    const j = await resp.json() as { path: string };
    return j.path;
  }

  /**
   * 检查服务是否可用
   */
  async isAvailable(): Promise<boolean> {
    try {
      await this.healthCheck();
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * 创建HTTP API适配器的单例实例
 */
let httpApiClient: HttpApiClient | null = null;

export function getHttpClient(): HttpApiClient | null {
  if (!httpApiClient) {
    httpApiClient = new HttpApiClient();
  }
  return httpApiClient;
}

export function setHttpClient(client: HttpApiClient): void {
  httpApiClient = client;
}

export function clearHttpClient(): void {
  if (httpApiClient) {
    httpApiClient.disconnectEventStream();
    httpApiClient = null;
  }
}

/**
 * 检查HTTP服务是否可用
 */
export async function checkHttpServiceAvailable(): Promise<boolean> {
  try {
    const client = getHttpClient();
    if (!client) return false;
    return await client.isAvailable();
  } catch {
    return false;
  }
}

export default HttpApiClient;