/**
 * AuthGate — 全屏登录/注册门控
 *
 * 未登录时覆盖整个应用，强制认证后才能进入主界面。
 * 包含登录与注册两个表单，带即时校验、记住我、加载态与错误提示。
 */

import { useEffect, useRef, useState } from "react";
import { Eye, EyeOff, LogIn, UserPlus, ShieldCheck, Loader2 } from "lucide-react";
import { useAuthStore } from "../store/auth";
import { useToast } from "../lib/toast";
import {
  validateUsername,
  validateEmail,
  validatePassword,
  AUTH_ERROR_MESSAGES,
  type AuthError,
} from "../lib/auth";

type Mode = "login" | "register";

interface FieldErrors {
  username?: string;
  email?: string;
  password?: string;
  confirmPassword?: string;
  identifier?: string;
}

export function AuthGate() {
  const { login, register, loading, error, clearError } = useAuthStore();
  const { showToast } = useToast();

  const [mode, setMode] = useState<Mode>("login");
  const [showPassword, setShowPassword] = useState(false);
  const [remember, setRemember] = useState(true);

  // 登录表单
  const [identifier, setIdentifier] = useState("");
  const [loginPassword, setLoginPassword] = useState("");

  // 注册表单
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const identifierRef = useRef<HTMLInputElement>(null);

  // 切换模式时清空错误
  useEffect(() => {
    setFieldErrors({});
    clearError();
  }, [mode, clearError]);

  // 自动聚焦
  useEffect(() => {
    identifierRef.current?.focus();
  }, [mode]);

  function switchMode(next: Mode) {
    setMode(next);
    setShowPassword(false);
  }

  // ─── 登录提交 ───
  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    const errors: FieldErrors = {};
    if (!identifier.trim()) errors.identifier = "请输入用户名或邮箱";
    if (!loginPassword) errors.password = "请输入密码";
    if (Object.keys(errors).length) {
      setFieldErrors(errors);
      return;
    }
    setFieldErrors({});
    const ok = await login(identifier.trim(), loginPassword, remember);
    if (ok) {
      showToast("登录成功", "info");
    }
  }

  // ─── 注册提交 ───
  async function handleRegister(e: React.FormEvent) {
    e.preventDefault();
    const errors: FieldErrors = {};
    const uErr = validateUsername(username);
    if (uErr) errors.username = AUTH_ERROR_MESSAGES[uErr as AuthError];
    const eErr = validateEmail(email);
    if (eErr) errors.email = AUTH_ERROR_MESSAGES[eErr as AuthError];
    const pErr = validatePassword(password);
    if (pErr) errors.password = AUTH_ERROR_MESSAGES[pErr as AuthError];
    if (password !== confirmPassword) errors.confirmPassword = AUTH_ERROR_MESSAGES.PASSWORD_MISMATCH;
    if (Object.keys(errors).length) {
      setFieldErrors(errors);
      return;
    }
    setFieldErrors({});
    const ok = await register(username.trim(), email.trim(), password, confirmPassword);
    if (ok) {
      showToast("注册成功，已自动登录", "info");
    }
  }

  const inputBase =
    "auth-input" + (fieldErrors.identifier || fieldErrors.username || fieldErrors.email ? " auth-input--error" : "");

  return (
    <div className="auth-gate" role="dialog" aria-modal="true" aria-label="用户认证">
      <div className="auth-gate__bg" aria-hidden="true" />
      <div className="auth-card">
        <div className="auth-card__header">
          <div className="auth-card__logo">
            <ShieldCheck size={28} strokeWidth={1.8} />
          </div>
          <h1 className="auth-card__title">EduShield 校园智盾</h1>
          <p className="auth-card__subtitle">
            {mode === "login" ? "登录以继续使用安全智能体平台" : "创建账户，开启安全防护之旅"}
          </p>
        </div>

        {error && (
          <div className="auth-alert" role="alert">
            {error}
          </div>
        )}

        {mode === "login" ? (
          <form className="auth-form" onSubmit={handleLogin} noValidate>
            <label className="auth-field">
              <span className="auth-field__label">用户名或邮箱</span>
              <input
                ref={identifierRef}
                type="text"
                className={inputBase}
                value={identifier}
                onChange={(e) => setIdentifier(e.target.value)}
                placeholder="请输入用户名或邮箱"
                autoComplete="username"
                disabled={loading}
              />
              {fieldErrors.identifier && (
                <span className="auth-field__error">{fieldErrors.identifier}</span>
              )}
            </label>

            <label className="auth-field">
              <span className="auth-field__label">密码</span>
              <div className="auth-input__wrap">
                <input
                  type={showPassword ? "text" : "password"}
                  className="auth-input"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  placeholder="请输入密码"
                  autoComplete="current-password"
                  disabled={loading}
                />
                <button
                  type="button"
                  className="auth-input__toggle"
                  onClick={() => setShowPassword((v) => !v)}
                  aria-label={showPassword ? "隐藏密码" : "显示密码"}
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              {fieldErrors.password && (
                <span className="auth-field__error">{fieldErrors.password}</span>
              )}
            </label>

            <label className="auth-checkbox">
              <input
                type="checkbox"
                checked={remember}
                onChange={(e) => setRemember(e.target.checked)}
                disabled={loading}
              />
              <span>记住我（7 天内免登录）</span>
            </label>

            <button type="submit" className="auth-btn auth-btn--primary" disabled={loading}>
              {loading ? (
                <Loader2 size={16} className="auth-btn__spinner" />
              ) : (
                <LogIn size={16} />
              )}
              <span>登录</span>
            </button>

            <p className="auth-switch">
              还没有账户？
              <button type="button" className="auth-switch__link" onClick={() => switchMode("register")}>
                立即注册
              </button>
            </p>
          </form>
        ) : (
          <form className="auth-form" onSubmit={handleRegister} noValidate>
            <label className="auth-field">
              <span className="auth-field__label">用户名</span>
              <input
                type="text"
                className="auth-input"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="3-20 位字母/数字/下划线"
                autoComplete="username"
                disabled={loading}
              />
              {fieldErrors.username && (
                <span className="auth-field__error">{fieldErrors.username}</span>
              )}
            </label>

            <label className="auth-field">
              <span className="auth-field__label">邮箱</span>
              <input
                type="email"
                className="auth-input"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="your@email.com"
                autoComplete="email"
                disabled={loading}
              />
              {fieldErrors.email && (
                <span className="auth-field__error">{fieldErrors.email}</span>
              )}
            </label>

            <label className="auth-field">
              <span className="auth-field__label">密码</span>
              <div className="auth-input__wrap">
                <input
                  type={showPassword ? "text" : "password"}
                  className="auth-input"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="至少 6 位"
                  autoComplete="new-password"
                  disabled={loading}
                />
                <button
                  type="button"
                  className="auth-input__toggle"
                  onClick={() => setShowPassword((v) => !v)}
                  aria-label={showPassword ? "隐藏密码" : "显示密码"}
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              {fieldErrors.password && (
                <span className="auth-field__error">{fieldErrors.password}</span>
              )}
            </label>

            <label className="auth-field">
              <span className="auth-field__label">确认密码</span>
              <input
                type="password"
                className="auth-input"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="再次输入密码"
                autoComplete="new-password"
                disabled={loading}
              />
              {fieldErrors.confirmPassword && (
                <span className="auth-field__error">{fieldErrors.confirmPassword}</span>
              )}
            </label>

            <button type="submit" className="auth-btn auth-btn--primary" disabled={loading}>
              {loading ? (
                <Loader2 size={16} className="auth-btn__spinner" />
              ) : (
                <UserPlus size={16} />
              )}
              <span>注册</span>
            </button>

            <p className="auth-switch">
              已有账户？
              <button type="button" className="auth-switch__link" onClick={() => switchMode("login")}>
                返回登录
              </button>
            </p>
          </form>
        )}

        <p className="auth-card__footer">
          数据保存在本地浏览器，密码经 SHA-256 哈希存储
        </p>
      </div>
    </div>
  );
}
