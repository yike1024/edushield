/**
 * UserMenu — 标题栏用户信息展示 + 注销下拉菜单
 *
 * 读取 useAuthStore 的 currentUser，渲染头像（用户名首字母）、用户名、
 * 邮箱、注册时间，以及"注销"按钮。未登录时不渲染。
 */

import { useEffect, useRef, useState } from "react";
import { LogOut, ChevronDown } from "lucide-react";
import { useAuthStore } from "../store/auth";
import { useToast } from "../lib/toast";

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString("zh-CN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    });
  } catch {
    return iso;
  }
}

export function UserMenu() {
  const { user, logout } = useAuthStore();
  const { showToast } = useToast();
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  // 点击外部关闭
  useEffect(() => {
    if (!open) return;
    function handleClick(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", handleClick);
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("keydown", handleKey);
    };
  }, [open]);

  if (!user) return null;

  const initial = user.username.charAt(0).toUpperCase();

  function handleLogout() {
    logout();
    setOpen(false);
    showToast("已注销登录", "info");
  }

  return (
    <div className="user-menu" ref={menuRef}>
      <button
        type="button"
        className="user-menu__trigger"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        title={user.username}
      >
        <span className="user-menu__avatar" aria-hidden="true">
          {initial}
        </span>
        <span className="user-menu__name">{user.username}</span>
        <ChevronDown
          size={14}
          className={"user-menu__chevron" + (open ? " user-menu__chevron--open" : "")}
        />
      </button>

      {open && (
        <div className="user-menu__dropdown" role="menu" aria-label="用户菜单">
          <div className="user-menu__profile">
            <span className="user-menu__avatar user-menu__avatar--large" aria-hidden="true">
              {initial}
            </span>
            <div className="user-menu__info">
              <div className="user-menu__info-name">{user.username}</div>
              <div className="user-menu__info-email">{user.email}</div>
              <div className="user-menu__info-meta">注册于 {formatDate(user.createdAt)}</div>
            </div>
          </div>
          <div className="user-menu__divider" />
          <button
            type="button"
            className="user-menu__item user-menu__item--danger"
            onClick={handleLogout}
            role="menuitem"
          >
            <LogOut size={15} />
            <span>注销登录</span>
          </button>
        </div>
      )}
    </div>
  );
}
