/**
 * AiSOC 集成指南（已对齐 docs/frontend-api.md）
 * 展示新 AiSOC 脑端 FastAPI（6657）的正确调用与 RealtimePanel 集成示例。
 * 本文件仅为示例/文档用途，不会被 AisocDashboard 直接调用。
 */

import { aisocApi, type CreateTaskInput } from './aisoc-api';
import RealtimePanel from '../components/RealtimePanel';

/**
 * 在现有App.tsx中集成实时面板的示例
 *
 * 将以下代码添加到App.tsx中：
 */

/*
// 1. 导入组件
import RealtimePanel from './components/RealtimePanel';
import { aisocApi, generateTaskId } from './lib/aisoc-api';

// 2. 在状态中添加
const [showRealtimePanel, setShowRealtimePanel] = useState(false);
const [authToken, setAuthToken] = useState<string>('your-auth-token');

// 3. 在渲染中添加面板
{showRealtimePanel && (
  <div className="fixed inset-0 z-50 bg-black bg-opacity-50">
    <div className="absolute right-0 top-0 h-full w-1/2 bg-white shadow-xl">
      <div className="flex items-center justify-between p-4 border-b">
        <h2 className="text-xl font-bold">实时监控</h2>
        <button
          onClick={() => setShowRealtimePanel(false)}
          className="p-2 hover:bg-gray-100 rounded"
        >
          关闭
        </button>
      </div>
      <RealtimePanel
        authToken={authToken}
        autoConnect={true}
        onTaskClick={(taskId) => {
          // 处理任务点击，跳转到任务详情页
          console.log('Task clicked:', taskId);
        }}
        onFindingClick={(finding) => {
          // 处理证据点击，显示证据详情
          console.log('Finding clicked:', finding);
        }}
      />
    </div>
  </div>
)}

// 4. 添加开关按钮
<button
  onClick={() => setShowRealtimePanel(!showRealtimePanel)}
  className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
>
  {showRealtimePanel ? '隐藏' : '显示'} 实时面板
</button>
*/

/**
 * 使用 API 客户端创建任务的示例（文档 §4.1 单 POST）
 */
export async function createAisocTaskExample() {
  try {
    const task: CreateTaskInput = {
      task: '对 http://example.com 做一次渗透测试，重点关注开放端口与已知 CVE',
      domain: 'pentest',
      target: 'http://example.com',
      // pipeline: 'data_leak', // 多阶段管道仅支持 data_leak，按需传
      tools: ['port_scan', 'dns_enum', 'cve_search'],
    };
    const result = await aisocApi.createTask(task);
    console.log('Task created (202):', result);
    return result;
  } catch (error) {
    console.error('Failed to create task:', error);
    throw error;
  }
}

/**
 * 查询任务证据的示例
 */
export async function getFindingsExample(taskId: string) {
  try {
    const findings = await aisocApi.getFindings(taskId);
    console.log('Findings:', findings);
    return findings;
  } catch (error) {
    console.error('Failed to get findings:', error);
    throw error;
  }
}

/**
 * 获取任务报告的示例
 */
export async function getReportExample(taskId: string) {
  try {
    const report = await aisocApi.getReport(taskId);
    console.log('Report:', report);
    return report;
  } catch (error) {
    console.error('Failed to get report:', error);
    throw error;
  }
}

/**
 * 知识库搜索的示例（已被 frontend-api.md 移除，保留占位说明）
 */
export async function searchKnowledgeExample(query: string) {
  // 注意：新版大脑协议不再提供 /api/knowledge 搜索接口（frontend-api.md 无此端点），
  // 任务上下文通过 POST /api/tasks 的 params 透传。此函数仅作兼容提示。
  console.warn('searchKnowledgeExample 已废弃：新协议无 /api/knowledge 接口', query);
  return [];
}

/**
 * 处理工具审批的示例（文档 §4.9 POST /api/approve：{task_id, action, decision}）
 */
export async function handleToolApprovalExample(taskId: string, action: string, decision: 'approved' | 'denied') {
  try {
    await aisocApi.approveTool(taskId, action, decision);
    console.log('Approval recorded:', { taskId, action, decision });
  } catch (error) {
    console.error('Failed to process approval:', error);
    throw error;
  }
}

/**
 * 审计导出示例（文档 §4.5 GET /api/tasks/{id}/export）
 */
export async function exportTaskExample(taskId: string) {
  try {
    const data = await aisocApi.exportTask(taskId);
    console.log('Exported audit JSON:', data);
    return data;
  } catch (error) {
    console.error('Failed to export task:', error);
    throw error;
  }
}

/**
 * Agent 忙闲状态示例（文档 §4.1c GET /api/agents/status，状态墙数据源）
 */
export async function getAgentsStatusExample() {
  try {
    const status = await aisocApi.getAgentsStatus();
    console.log('Agent status:', status);
    return status;
  } catch (error) {
    console.error('Failed to get agents status:', error);
    throw error;
  }
}

/**
 * 告警样例示例（文档 §4.7 GET /api/data/alarms）
 */
export async function getAlarmsExample(limit = 10) {
  try {
    const alarms = await aisocApi.getAlarms(limit);
    console.log('Alarms:', alarms);
    return alarms;
  } catch (error) {
    console.error('Failed to get alarms:', error);
    throw error;
  }
}

/**
 * 与现有Wails桥接的集成示例
 *
 * 如果需要同时支持Wails和新的HTTP API，可以创建一个适配器：
 */
export class HybridApiAdapter {
  private wailsBridge: any; // 现有的Wails bridge
  private httpApi: typeof aisocApi;

  constructor(wailsBridge: any) {
    this.wailsBridge = wailsBridge;
    this.httpApi = aisocApi;
  }

  async submitTask(input: string): Promise<void> {
    // 优先使用Wails，如果不可用则回退到HTTP API
    if (this.wailsBridge && window.runtime) {
      try {
        return await this.wailsBridge.Submit(input);
      } catch (error) {
        console.warn('Wails bridge failed, falling back to HTTP API:', error);
      }
    }

    // 回退到HTTP API
    const task = this.parseInputToTask(input);
    await this.httpApi.createTask(task);
  }

  private parseInputToTask(input: string): CreateTaskInput {
    // 简单的输入解析逻辑
    // 实际实现需要更复杂的解析
    return {
      task: input,
      domain: 'pentest',
      target: input,
    };
  }
}

/**
 * 配置说明
 *
 * 1. 更新环境变量配置（.env文件）：
 *
 * VITE_BRAIN_API_URL=http://127.0.0.1:6657/api
 * VITE_AUTH_TOKEN=your-auth-token
 *
 * 2. 在vite.config.ts中添加代理配置（如果需要）：
 *
 * server: {
 *   proxy: {
 *     '/api': {
 *       target: 'http://127.0.0.1:6657',
 *       changeOrigin: true,
 *     },
 *   },
 * }
 *
 * 3. 在路由中添加实时面板（如果使用路由）：
 *
 * import RealtimePanel from './components/RealtimePanel';
 *
 * const routes = [
 *   // ... 其他路由
 *   {
 *     path: '/realtime',
 *     element: <RealtimePanel />,
 *   },
 * ];
 */

/**
 * 数据流架构说明
 *
 * 现有架构：
 * React UI ←→ Wails Bridge ←→ Go Backend
 *
 * 新架构（可选集成）：
 * React UI ←→ Wails Bridge ←→ Go Backend
 *              ↕ HTTP API
 *           Brain API (FastAPI)
 *              ↕ SSE
 *           Realtime Panel
 *
 * 集成策略：
 * 1. 保持现有Wails功能不变
 * 2. 添加新的HTTP API客户端作为可选功能
 * 3. 实时面板可以独立显示，不影响现有UI
 * 4. 提供配置开关，允许用户选择使用哪种通信方式
 */

/**
 * 迁移检查清单
 *
 * - [ ] 配置大脑API端点URL
 * - [ ] 设置认证token
 * - [ ] 测试API连接（health check）
 * - [ ] 集成实时面板组件
 * - [ ] 添加任务创建功能
 * - [ ] 实现证据查看功能
 * - [ ] 实现报告生成功能
 * - [ ] 配置SSE事件流
 * - [ ] 添加错误处理
 * - [ ] 更新用户界面
 * - [ ] 文档更新
 * - [ ] 用户培训
 */

export default {
  aisocApi,
  RealtimePanel,
  createAisocTaskExample,
  getFindingsExample,
  getReportExample,
  searchKnowledgeExample,
  handleToolApprovalExample,
  exportTaskExample,
  getAgentsStatusExample,
  getAlarmsExample,
  HybridApiAdapter,
};