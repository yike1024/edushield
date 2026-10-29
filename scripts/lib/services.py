#!/usr/bin/env python3
"""config/services.json 的读取辅助（给 scripts/*.sh 用，不依赖 jq / node）。

子命令：
    list [--group G] [--only a,b] [--include-disabled]
        -> 每行 TSV：id  order  port  cwd  healthPath  healthExpect  auth
                     cookieName  cookieVar  postPath  postMethod  postCookieVar
    env <id>      -> 已合并 env 文件 + ${VAR} 展开后的 sh 赋值语句（eval 用）
    cmd <id>      -> 展开后的启动命令，每行一个 argv
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def load_cfg() -> dict:
    return json.loads((ROOT / "config/services.json").read_text(encoding="utf-8"))


def parse_env(path: Path) -> dict:
    data: dict[str, str] = {}
    if not path.is_file():
        return data
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        data[k.strip()] = v
    return data


def expand(text: str, env: dict) -> str:
    return VAR.sub(lambda m: (env.get(m.group(1)) or m.group(2) or ""), text)


def select(cfg: dict, only=None, group=None, include_disabled=False) -> list[dict]:
    svcs = list(cfg["services"])
    if not include_disabled and not only:
        svcs = [s for s in svcs if s.get("enabled", True)]
    if only:
        svcs = [s for s in svcs if s["id"] in only]
    if group:
        svcs = [s for s in svcs if s.get("group") == group]
    return sorted(svcs, key=lambda s: s.get("startOrder", 999))


def find(cfg: dict, sid: str) -> dict:
    for s in cfg["services"]:
        if s["id"] == sid:
            return s
    raise SystemExit(f"unknown service id: {sid}")


def svc_env(svc: dict) -> dict:
    merged: dict[str, str] = {}
    for rel in [svc.get("envFile")] + list(svc.get("extraEnvFiles") or []):
        if rel:
            merged.update(parse_env(ROOT / rel))
    return merged


def cmd_list(args) -> int:
    cfg = load_cfg()
    only = set(args.only.split(",")) if args.only else None
    for s in select(cfg, only, args.group, args.include_disabled):
        h = s.get("health") or {}
        p = s.get("postStart") or {}
        print("\t".join(str(x) for x in [
            s["id"], s.get("startOrder", 999), s.get("group", ""), s["port"], s["cwd"],
            h.get("path", "/"), h.get("expect", 200), h.get("auth", "none"),
            h.get("cookieName", ""), h.get("cookieVar", ""),
            p.get("path", ""), p.get("method", ""), p.get("cookieVar", ""),
        ]))
    return 0


def cmd_env(args) -> int:
    cfg = load_cfg()
    svc = find(cfg, args.id)
    env = svc_env(svc)
    for k, v in env.items():
        print(f"export {k}={shlex.quote(v)}")
    return 0


def cmd_cmd(args) -> int:
    cfg = load_cfg()
    svc = find(cfg, args.id)
    env = svc_env(svc)
    for a in svc["cmd"]:
        print(expand(str(a), env))
    return 0


def cmd_post(args) -> int:
    """输出 postStart 的 TSV：path  method  cookieVar  bodyJson（无则空串）。"""
    cfg = load_cfg()
    svc = find(cfg, args.id)
    p = svc.get("postStart") or {}
    print("\t".join([
        p.get("path", ""),
        p.get("method", "POST"),
        p.get("cookieVar", ""),
        json.dumps(p.get("body") or {}, separators=(",", ":")),
    ]))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="services.json helper")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list")
    p_list.add_argument("--group", default="")
    p_list.add_argument("--only", default="")
    p_list.add_argument("--include-disabled", action="store_true")
    p_list.set_defaults(func=cmd_list)

    p_env = sub.add_parser("env")
    p_env.add_argument("id")
    p_env.set_defaults(func=cmd_env)

    p_cmd = sub.add_parser("cmd")
    p_cmd.add_argument("id")
    p_cmd.set_defaults(func=cmd_cmd)

    p_post = sub.add_parser("post")
    p_post.add_argument("id")
    p_post.set_defaults(func=cmd_post)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
