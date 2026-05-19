#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import sqlite3
from typing import Any

import stallion_gateway


def load_gateway_file(path: pathlib.Path) -> dict[str, Any]:
    if not path.exists():
        return {"servers": {}}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit(f"invalid gateway config: {path}")
    payload.setdefault("servers", {})
    if not isinstance(payload["servers"], dict):
        raise SystemExit(f"invalid gateway config: {path}")
    return payload


def sqlite_schema_markdown(db_path: pathlib.Path, *, title: str | None = None) -> str:
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        heading = title or f"SQLite schema for {db_path.name}"
        parts = [heading]
        for (table_name,) in rows:
            parts.append("")
            parts.append(f"Table `{table_name}`")
            escaped_name = table_name.replace("'", "''")
            columns = conn.execute(f"PRAGMA table_info('{escaped_name}')").fetchall()
            if not columns:
                parts.append("- no columns discovered")
                continue
            for _, column_name, column_type, notnull, default_value, pk in columns:
                extras: list[str] = []
                if column_type:
                    extras.append(str(column_type))
                if pk:
                    extras.append("primary key")
                if notnull:
                    extras.append("not null")
                if default_value is not None:
                    extras.append(f"default={default_value}")
                suffix = f" ({', '.join(extras)})" if extras else ""
                parts.append(f"- `{column_name}`{suffix}")
        return "\n".join(parts).strip()
    finally:
        conn.close()


def build_context(
    args: argparse.Namespace,
    sql_targets: list[str],
    pack_context: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    pack_context = pack_context or {}
    text_parts: list[str] = []
    if args.context_text:
        text_parts.append(str(args.context_text).strip())
    if args.context_file:
        context_path = pathlib.Path(args.context_file).expanduser()
        if not context_path.is_absolute():
            context_path = context_path.resolve()
        text_parts.append(context_path.read_text(encoding="utf-8").strip())
    if args.sqlite_schema:
        schema_text = sqlite_schema_markdown(
            pathlib.Path(args.sqlite_schema).expanduser().resolve(),
            title=args.schema_title,
        )
        text_parts.append(schema_text)
    if not any(part for part in text_parts):
        return None
    default_inject = pack_context.get("inject_into")
    inject_into = (
        args.inject_into
        or ([str(item) for item in default_inject] if isinstance(default_inject, list) else [])
        or sql_targets
        or ["*"]
    )
    position = args.context_position or str(pack_context.get("position") or "append")
    label = args.context_label or str(pack_context.get("label") or "Stallion Context")
    return {
        "text": "\n\n".join(part for part in text_parts if part),
        "inject_into": inject_into,
        "position": position,
        "label": label,
    }


def add_server(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root).resolve()
    config_path = pathlib.Path(args.config).expanduser()
    if not config_path.is_absolute():
        config_path = (root / config_path).resolve()
    payload = load_gateway_file(config_path)
    servers = payload.setdefault("servers", {})
    if not isinstance(servers, dict):
        raise SystemExit(f"invalid gateway config: {config_path}")

    pack_catalog = stallion_gateway.load_pack_catalog(root)
    if args.pack and args.pack not in pack_catalog:
        raise SystemExit(f"unknown MCP pack: {args.pack}")

    sql_targets = list(args.sql_tool)
    if args.pack:
        pack = pack_catalog.get(args.pack, {})
        sql_policy = pack.get("sql_policy") or {}
        if not sql_targets and isinstance(sql_policy, dict):
            sql_targets = [str(item) for item in sql_policy.get("tool_names", []) if isinstance(item, str)]
        pack_context = pack.get("context") if isinstance(pack.get("context"), dict) else {}
    else:
        pack_context = {}

    spec: dict[str, Any] = {
        "command": args.command,
        "args": list(args.arg),
    }
    if args.env:
        env: dict[str, str] = {}
        for item in args.env:
            if "=" not in item:
                raise SystemExit(f"invalid env override: {item} (expected KEY=VALUE)")
            key, value = item.split("=", 1)
            env[key] = value
        spec["env"] = env
    if args.cwd:
        spec["cwd"] = args.cwd
    if args.pack:
        spec["pack"] = args.pack

    context = build_context(args, sql_targets, pack_context)
    if context is not None:
        spec["context"] = context

    if sql_targets:
        sql_policy: dict[str, Any] = {"enabled": True, "mode": "readonly", "tool_names": sql_targets}
        if args.sql_arg:
            sql_policy["sql_arg"] = args.sql_arg
        spec["sql_policy"] = sql_policy

    servers[str(args.server_id)] = spec
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    runtime_hint = ""
    if args.runtime:
        runtime_hint = f"\nnext: ./bin/stallion generate-runtime-config {args.runtime} {args.profile}"
    print(f"updated {config_path} with server {args.server_id}{runtime_hint}")
    return 0


def list_packs(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root).resolve()
    catalog = stallion_gateway.load_pack_catalog(root)
    if args.json:
        print(json.dumps(catalog, indent=2))
        return 0
    if not catalog:
        print("no MCP packs available")
        return 0
    for name in sorted(catalog):
        spec = catalog[name]
        sql_policy = spec.get("sql_policy") or {}
        targets = ", ".join(sql_policy.get("tool_names", [])) if isinstance(sql_policy, dict) else ""
        print(name)
        if targets:
            print(f"  sql tools: {targets}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Add upstream MCP servers to the Stallion gateway config")
    parser.add_argument("--root", default=pathlib.Path(__file__).resolve().parents[1])
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list-packs", help="List built-in MCP packs")
    list_parser.add_argument("--json", action="store_true")
    list_parser.set_defaults(func=list_packs)

    add_parser = subparsers.add_parser("add", help="Add or update an upstream MCP server")
    add_parser.add_argument("server_id")
    add_parser.add_argument("--config", default="config/gateway.json")
    add_parser.add_argument("--command", required=True)
    add_parser.add_argument("--arg", action="append", default=[])
    add_parser.add_argument("--env", action="append", default=[])
    add_parser.add_argument("--cwd")
    add_parser.add_argument("--pack")
    add_parser.add_argument("--profile", default="balanced")
    add_parser.add_argument("--runtime", choices=["codex", "cursor", "windsurf", "claude-desktop", "generic-mcp"])
    add_parser.add_argument("--context-text")
    add_parser.add_argument("--context-file")
    add_parser.add_argument("--inject-into", action="append", default=[])
    add_parser.add_argument("--context-position", choices=["prepend", "append"])
    add_parser.add_argument("--context-label")
    add_parser.add_argument("--sqlite-schema")
    add_parser.add_argument("--schema-title")
    add_parser.add_argument("--sql-tool", action="append", default=[])
    add_parser.add_argument("--sql-arg")
    add_parser.set_defaults(func=add_server)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
