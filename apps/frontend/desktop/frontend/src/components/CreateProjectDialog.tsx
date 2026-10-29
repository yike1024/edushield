/**
 * CreateProjectDialog — 浏览器模式「新建评估项目」对话框（17 号方案 · 方案 B）
 *
 * Web 形态没有原生选目录对话框，"添加新项目"改为创建一个评估项目：
 * 一个项目 = 一次安全评估对象（名称 + 评估目标 + 描述 + 颜色）。
 *
 * 只负责收集输入与校验；提交与后续导航（SwitchWorkspace / 开空白会话 / 刷树）
 * 由 App 编排，提交失败时在对话框内展示错误，不自动关闭。
 */

import { useEffect, useRef, useState } from "react";
import { FolderPlus, Loader2, Target, X } from "lucide-react";
import { PROJECT_COLOR_OPTIONS, projectColorValue } from "../lib/projectColors";

export interface CreateProjectInput {
  name: string;
  target?: string;
  description?: string;
  color?: string;
}

interface Props {
  onClose: () => void;
  onSubmit: (input: CreateProjectInput) => Promise<void>;
}

const NAME_MAX = 40;
const TARGET_MAX = 200;

export default function CreateProjectDialog({ onClose, onSubmit }: Props) {
  const [name, setName] = useState("");
  const [target, setTarget] = useState("");
  const [description, setDescription] = useState("");
  // 默认色：空串=跟随主题默认强调色
  const [color, setColor] = useState<string>("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const nameRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    nameRef.current?.focus();
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !submitting) {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, submitting]);

  const canSubmit = name.trim().length > 0 && !submitting;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmedName = name.trim();
    if (!trimmedName) {
      setError("请填写项目名称");
      nameRef.current?.focus();
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await onSubmit({
        name: trimmedName,
        target: target.trim() || undefined,
        description: description.trim() || undefined,
        color: color || undefined,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err) || "创建失败，请重试");
      setSubmitting(false);
    }
  }

  return (
    <div
      className="cp-dialog-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !submitting) onClose();
      }}
      role="presentation"
    >
      <form
        className="cp-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="新建评估项目"
        onSubmit={handleSubmit}
      >
        <div className="cp-dialog__header">
          <div className="cp-dialog__title">
            <FolderPlus size={16} aria-hidden="true" />
            <span>新建评估项目</span>
          </div>
          <button
            type="button"
            className="cp-dialog__close"
            onClick={onClose}
            disabled={submitting}
            aria-label="关闭"
          >
            <X size={15} aria-hidden="true" />
          </button>
        </div>

        <p className="cp-dialog__hint">
          项目对应一次安全评估行动（如某中学官网、某网段）。项目下可发起多个会话，
          任务与发现自动归集到项目。
        </p>

        <label className="cp-field">
          <span className="cp-field__label">项目名称<span className="cp-field__required">*</span></span>
          <input
            ref={nameRef}
            type="text"
            className="cp-field__input"
            value={name}
            maxLength={NAME_MAX}
            onChange={(e) => setName(e.target.value)}
            placeholder="例：某中学官网安全评估"
            disabled={submitting}
          />
        </label>

        <label className="cp-field">
          <span className="cp-field__label">
            <Target size={11} aria-hidden="true" />
            评估目标
          </span>
          <input
            type="text"
            className="cp-field__input"
            value={target}
            maxLength={TARGET_MAX}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="IP / CIDR / 域名 / URL，例：10.20.1.0/24 或 www.example.edu.cn"
            disabled={submitting}
          />
          <span className="cp-field__help">发起任务时默认使用该目标，可在对话中临时修改。</span>
        </label>

        <label className="cp-field">
          <span className="cp-field__label">项目描述</span>
          <textarea
            className="cp-field__input cp-field__textarea"
            value={description}
            rows={3}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="评估范围、时间窗口、联系人等备注（可选）"
            disabled={submitting}
          />
        </label>

        <div className="cp-field">
          <span className="cp-field__label">标记颜色</span>
          <div className="cp-colors" role="radiogroup" aria-label="项目颜色">
            {PROJECT_COLOR_OPTIONS.map((option) => {
              const value = projectColorValue(option.key);
              const selected = color === option.key;
              return (
                <button
                  key={option.key || "default"}
                  type="button"
                  role="radio"
                  aria-checked={selected}
                  title={option.key || "默认"}
                  className={`cp-colors__swatch${selected ? " cp-colors__swatch--selected" : ""}`}
                  style={value ? { background: value } : undefined}
                  onClick={() => setColor(option.key)}
                  disabled={submitting}
                >
                  {!value && <span className="cp-colors__default" aria-hidden="true" />}
                </button>
              );
            })}
          </div>
        </div>

        {error && (
          <div className="cp-dialog__error" role="alert">{error}</div>
        )}

        <div className="cp-dialog__actions">
          <button
            type="button"
            className="btn cp-dialog__cancel"
            onClick={onClose}
            disabled={submitting}
          >
            取消
          </button>
          <button
            type="submit"
            className="btn cp-dialog__submit"
            disabled={!canSubmit}
          >
            {submitting ? <Loader2 size={14} className="cp-spin" aria-hidden="true" /> : <FolderPlus size={14} aria-hidden="true" />}
            创建并开始对话
          </button>
        </div>
      </form>
    </div>
  );
}
