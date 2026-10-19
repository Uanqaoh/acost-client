#!/usr/bin/env python3
"""Standard-library CLI for Acost's explicitly configured shared API.

Examples:
  python3 ledgerctl.py summary --month 2026-10
  python3 ledgerctl.py add --amount 26.07 --date 2026-10-14 \
      --time 10:53 --merchant 'Nations Fresh Foods' --key RECEIPT-STABLE-KEY
  python3 ledgerctl.py add --json < entry.json

Run configure once with an HTTPS URL, or supply LEDGER_URL and LEDGER_TOKEN.
Missing configuration never falls back to localhost. Secrets are never printed.
"""

import argparse
import base64
import datetime as dt
from decimal import Decimal, InvalidOperation
import json
import getpass
import io
import zipfile
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

from client_config import ClientError, Connection, default_config, load_connection, save_connection

_ACTIVE_CONNECTION = None
_CONFIG_PATH = None

try:
    from zoneinfo import ZoneInfo
except ImportError:  # Python 3.8 can still run the CLI with explicit dates.
    ZoneInfo = None


MAX_RECEIPT_BYTES = 8 * 1024 * 1024
ENTRY_TYPES = ("expense", "income", "transfer")


class LedgerError(Exception):
    """A user-facing error that does not contain authentication credentials."""

    def __init__(self, message, *, status=None, details=None):
        super().__init__(message)
        self.status = status
        self.details = details


def amount_cents(value):
    """Convert a positive decimal string to cents without float rounding."""
    value = str(value).strip()
    if not re.fullmatch(r"\+?(?:\d+(?:\.\d*)?|\.\d+)", value):
        raise LedgerError("金额必须是正十进制数，例如 26.07。")
    try:
        amount = Decimal(value)
    except InvalidOperation:
        raise LedgerError("金额无效。") from None
    if amount.as_tuple().exponent < -2:
        raise LedgerError("金额最多允许两位小数。")
    if amount <= 0:
        raise LedgerError("金额必须大于 0。")
    # The backend stores SQLite INTEGER cents; keep values within its range.
    cents = amount * 100
    if cents > 9223372036854775807:
        raise LedgerError("金额超出支持范围。")
    return int(cents)


def check_date(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise LedgerError("日期必须为 YYYY-MM-DD。")
    try:
        dt.date.fromisoformat(value)
    except ValueError:
        raise LedgerError("日期无效。") from None
    return value


def check_time(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{2}:\d{2}", value):
        raise LedgerError("时间必须为 HH:MM。")
    try:
        dt.time.fromisoformat(value)
    except ValueError:
        raise LedgerError("时间无效。") from None
    return value


def check_month(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}", value):
        raise LedgerError("月份必须为 YYYY-MM。")
    check_date(value + "-01")
    return value


def toronto_now():
    """Use Toronto time; never silently substitute the machine's timezone."""
    if ZoneInfo is not None:
        try:
            return dt.datetime.now(ZoneInfo("America/Toronto"))
        except (KeyError, ValueError):
            pass
    # Minimal Linux installs sometimes omit the IANA timezone database. UTC is
    # an explicit, documented fallback rather than guessing EST/EDT offsets.
    print("提示：系统缺少 America/Toronto 时区数据，默认日期使用 UTC；"
          "可显式提供 --date，或安装系统 tzdata。", file=sys.stderr)
    return dt.datetime.now(dt.timezone.utc)


def read_json():
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise LedgerError("标准输入不是有效 JSON：" + str(exc)) from None
    if not isinstance(payload, dict):
        raise LedgerError("--json 必须接收一条 JSON 对象。")
    return payload


def validate_payload(payload, *, creating=False, refund=False):
    """Validate supplied values, leaving absent JSON fields absent."""
    if creating or refund:
        missing = [field for field in ("amount_cents", "date") if field not in payload]
        if missing:
            raise LedgerError("JSON 缺少必填字段：" + ", ".join(missing))
    if "amount_cents" in payload:
        value = payload["amount_cents"]
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise LedgerError("amount_cents 必须为大于 0 的整数分。")
        if value > 9223372036854775807:
            raise LedgerError("amount_cents 超出支持范围。")
    if "date" in payload:
        check_date(payload["date"])
    if "time" in payload and payload["time"] is not None:
        check_time(payload["time"])
    if "currency" in payload and payload["currency"] != "CAD":
        raise LedgerError("当前账本只支持 CAD。")
    if "type" in payload and payload["type"] not in ENTRY_TYPES:
        raise LedgerError("type 必须为 expense、income 或 transfer。")
    if "idempotency_key" in payload:
        if not isinstance(payload["idempotency_key"], str) or not payload["idempotency_key"].strip():
            raise LedgerError("idempotency_key 必须为非空字符串。")
    if "duplicate_acknowledgements" in payload:
        acknowledged = payload["duplicate_acknowledgements"]
        if (not isinstance(acknowledged, list)
                or any(not isinstance(value, str) or not value.strip() for value in acknowledged)
                or len(set(acknowledged)) != len(acknowledged)):
            raise LedgerError("duplicate_acknowledgements 必须是不重复的非空账单 ID 字符串数组。")
    return payload


def command_payload(args):
    fields = ("amount", "date", "time", "merchant", "note", "category", "account",
              "to_account", "receipt_url", "type")
    if args.json:
        conflicts = [name for name in fields if getattr(args, name, None) is not None]
        if args.unknown_time:
            conflicts.append("unknown_time")
        if conflicts:
            raise LedgerError("--json 不可同时使用字段选项：" + ", ".join(conflicts))
        payload = read_json()
    else:
        payload = {}
        if args.command in ("add", "refund"):
            if args.amount is None:
                raise LedgerError("请提供 --amount，或使用 --json 输入 amount_cents。")
            payload["date"] = args.date or toronto_now().strftime("%Y-%m-%d")
            payload["time"] = args.time
        for field in fields:
            value = getattr(args, field, None)
            if value is not None:
                payload["amount_cents" if field == "amount" else field] = (
                    amount_cents(value) if field == "amount" else value
                )
        if args.unknown_time:
            payload["time"] = None
        if args.command == "add":
            payload.setdefault("type", "expense")
            payload.setdefault("account", "Spending")
            payload.setdefault("category", "餐饮-Grocery")
    if args.currency is not None:
        payload["currency"] = args.currency
    if args.key is not None:
        if "idempotency_key" in payload and payload["idempotency_key"] != args.key:
            raise LedgerError("--key 与 JSON 中的 idempotency_key 不一致。")
        payload["idempotency_key"] = args.key
    acknowledged = getattr(args, "acknowledge_duplicate", None)
    if acknowledged is not None:
        if ("duplicate_acknowledgements" in payload
                and payload["duplicate_acknowledgements"] != acknowledged):
            raise LedgerError("--acknowledge-duplicate 与 JSON 中的 duplicate_acknowledgements 不一致。")
        payload["duplicate_acknowledgements"] = acknowledged
    if args.command in ("add", "refund"):
        payload.setdefault("time", None)
    elif "duplicate_acknowledgements" in payload:
        raise LedgerError("duplicate_acknowledgements 仅用于新增或退款。")
    if args.command == "edit" and not payload:
        raise LedgerError("请至少提供一个要修改的字段。")
    validate_payload(payload, creating=args.command == "add", refund=args.command == "refund")
    # Currency is fixed by this backend rather than a mutable entry attribute.
    payload.pop("currency", None)
    return payload


def connection():
    global _ACTIVE_CONNECTION
    if _ACTIVE_CONNECTION is None:
        path = _CONFIG_PATH or os.environ.get("LEDGER_CONFIG") or default_config("grok")
        try:
            _ACTIVE_CONNECTION = load_connection(path)
        except ClientError as error:
            raise LedgerError(str(error)) from None
    return _ACTIVE_CONNECTION


def api_request(method, path, *, payload=None, query=None):
    try:
        raw, _ = connection().request(method, "/api/" + path.lstrip("/"),
                                      payload=payload, query=query, max_bytes=256 * 1024 * 1024)
        return raw
    except ClientError as error:
        raise LedgerError(str(error), status=error.status, details=error.details) from None


def positive_version(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise LedgerError("expected_version 必须是读取原单返回的正整数版本号。")
    return value


def require_saved_entry(result):
    if not isinstance(result, dict) or not isinstance(result.get("entry"), dict) or not result["entry"].get("id"):
        raise LedgerError("服务未返回实际保存的账单 ID，不能确认已保存；请用同一幂等键核对或重试。")
    return result


def configure_client(args):
    if not args.url:
        raise LedgerError("配置共享模式需要 --url https://你的服务地址。")
    if args.token_stdin:
        token = sys.stdin.readline().rstrip("\r\n")
    elif sys.stdin.isatty():
        token = getpass.getpass("当前 Grok 账号专属访问凭据（输入不显示）：").strip()
    else:
        raise LedgerError("请在交互终端输入凭据，或使用 --token-stdin 安全传入；不要放在命令参数中。")
    try:
        client = Connection(args.url, token)
        raw, _ = client.request("GET", "/api/meta")
        meta = json_response(raw)
        role = meta.get("client", {}).get("role")
        if role not in {"ai", "admin", "readonly"}:
            raise LedgerError("服务没有返回共享客户端角色，配置未保存。")
        path = _CONFIG_PATH or os.environ.get("LEDGER_CONFIG") or default_config("grok")
        storage = save_connection(path, client.url, token)
        return {"ok": True, "mode": "shared", "role": role, "credential_storage": storage}
    except ClientError as error:
        raise LedgerError(str(error)) from None


def json_response(raw):
    if not raw:
        return {"ok": True}
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise LedgerError("服务返回了无效 JSON。") from None


def save_output(path, raw, overwrite):
    destination = Path(path).expanduser()
    try:
        with destination.open("wb" if overwrite else "xb") as output:
            output.write(raw)
    except FileExistsError:
        raise LedgerError("输出文件已存在；如需覆盖，请显式使用 --overwrite。") from None
    except OSError as exc:
        raise LedgerError("无法保存文件：" + str(exc)) from None
    return {"ok": True, "output": str(destination.resolve()), "bytes": len(raw)}


def redact_token(value, token):
    """Avoid displaying a token even if a server unexpectedly reflects it."""
    if not token:
        return value
    if isinstance(value, str):
        return value.replace(token, "[redacted]")
    if isinstance(value, list):
        return [redact_token(item, token) for item in value]
    if isinstance(value, dict):
        return {redact_token(key, token): redact_token(item, token)
                for key, item in value.items()}
    return value


def entry_path(entry_id):
    if not str(entry_id).strip():
        raise LedgerError("账单 ID 不能为空。")
    return "entries/" + urllib.parse.quote(str(entry_id), safe="")


def execute(args):
    command = args.command
    if command == "configure":
        return configure_client(args)
    if command == "get":
        return json_response(api_request("GET", entry_path(args.id), query={"include_deleted": "true"} if args.include_deleted else None))
    if command in ("meta", "health"):
        return json_response(api_request("GET", command))
    if command in ("list", "summary"):
        query = {}
        for field in ("month", "q", "account", "category", "type", "limit", "offset"):
            value = getattr(args, field, None)
            if value is not None:
                query[field] = check_month(value) if field == "month" else value
        if command == "list":
            if args.limit < 1 or args.limit > 500 or args.offset < 0:
                raise LedgerError("limit 必须为 1–500，offset 不能小于 0。")
        return json_response(api_request("GET", "entries" if command == "list" else "summary", query=query))
    if command in ("add", "refund", "edit"):
        payload = command_payload(args)
        if command == "edit":
            supplied = payload.get("expected_version")
            if args.expected_version is not None:
                if supplied is not None and supplied != args.expected_version:
                    raise LedgerError("--expected-version 与 JSON 版本不一致。")
                supplied = args.expected_version
            payload["expected_version"] = positive_version(supplied)
        elif not payload.get("idempotency_key"):
            raise LedgerError("新增或退款必须提供稳定 --key / idempotency_key，重试沿用同一键。")
        path = "entries" if command == "add" else entry_path(args.id)
        if command == "refund":
            path += "/refunds"
        return require_saved_entry(json_response(api_request("PATCH" if command == "edit" else "POST", path, payload=payload)))
    if command in ("delete", "restore"):
        path = entry_path(args.id) + ("/restore" if command == "restore" else "")
        return json_response(api_request("DELETE" if command == "delete" else "POST", path,
                                         payload={"expected_version": positive_version(args.expected_version)}))
    if command == "upload":
        source = Path(args.file).expanduser()
        try:
            if not source.is_file():
                raise LedgerError("小票路径必须是文件。")
            if source.stat().st_size > MAX_RECEIPT_BYTES:
                raise LedgerError("小票文件不能超过 8 MB。")
            with source.open("rb") as stream:
                data = stream.read(MAX_RECEIPT_BYTES + 1)
        except OSError as exc:
            raise LedgerError("无法读取小票：" + str(exc)) from None
        if len(data) > MAX_RECEIPT_BYTES:
            raise LedgerError("小票文件不能超过 8 MB。")
        if not data:
            raise LedgerError("小票文件为空。")
        return json_response(api_request("POST", "receipts", payload={
            "filename": source.name,
            "data_base64": base64.b64encode(data).decode("ascii"),
        }))
    if command in ("export", "backup"):
        # Check before requesting, and use exclusive creation again when saving.
        destination = Path(args.output).expanduser()
        if destination.exists() and not args.overwrite:
            raise LedgerError("输出文件已存在；如需覆盖，请显式使用 --overwrite。")
        raw = api_request("GET", command)
        if command == "export":
            json_response(raw)
        elif connection().mode == "shared":
            try:
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    names = archive.namelist()
                    if "manifest.json" not in names or not any(name.endswith(".sqlite3") for name in names):
                        raise ValueError()
                    json.loads(archive.read("manifest.json"))
            except (zipfile.BadZipFile, ValueError, KeyError):
                raise LedgerError("服务返回的备份不是有效的完整备份包。") from None
        elif not raw.startswith(b"SQLite format 3\x00"):
            raise LedgerError("本地原型返回的备份不是有效 SQLite 文件。")
        return save_output(destination, raw, args.overwrite)
    raise LedgerError("未知命令。")


def add_payload_options(parser, *, refund=False, editing=False):
    parser.add_argument("--json", action="store_true", help="从标准输入读取单条原始 JSON 对象")
    parser.add_argument("--amount", help="正金额，最多两位小数；例如 26.07")
    parser.add_argument("--currency", choices=("CAD",), help="目前只支持 CAD")
    parser.add_argument("--date", help="YYYY-MM-DD；添加/退款默认多伦多当天")
    time_options = parser.add_mutually_exclusive_group()
    time_options.add_argument("--time", help="实际时间 HH:MM；添加/退款省略时标记为时间未记录")
    time_options.add_argument("--unknown-time", action="store_true", help="明确将时间标记为未记录；编辑时可清除占位时间")
    parser.add_argument("--note", help="备注")
    parser.add_argument("--key", help="稳定去重键；重试同笔录入必须使用相同键")
    if not editing:
        parser.add_argument("--acknowledge-duplicate", action="append", metavar="ID",
                            help="核对并确认是另一笔交易后，逐个填写疑似重复账单 ID；可重复使用")
    if not refund:
        parser.add_argument("--type", choices=ENTRY_TYPES, help="添加默认为 expense")
        parser.add_argument("--merchant", help="商家")
        parser.add_argument("--category", help="添加默认为 餐饮-Grocery")
        parser.add_argument("--account", help="添加默认为 Spending")
        parser.add_argument("--to-account", help="转账的收款账户")
        parser.add_argument("--receipt-url", help="上传接口返回的小票 URL")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Acost API 命令行：查询、录入、退款、编辑、撤销与备份。",
        epilog="默认共享模式：configure 保存 HTTPS 地址与凭据，或 LEDGER_URL/LEDGER_TOKEN。没有本地默认地址。"
               "--json 模式不会补猜金额或日期。",
    )
    parser.add_argument("--config", type=Path, help="私有配置路径；默认用户配置目录 grok.json")
    commands = parser.add_subparsers(dest="command", required=True)
    config = commands.add_parser("configure", help="验证并保存共享 HTTPS 地址与专属凭据")
    config.add_argument("--url", required=True)
    config.add_argument("--token-stdin", action="store_true", help="从标准输入读取一行凭据，避免命令历史")
    get = commands.add_parser("get", help="按真实 ID 读取原单及当前版本，支持跨月查询")
    get.add_argument("id")
    get.add_argument("--include-deleted", action="store_true", help="恢复前读取已删除原单")
    commands.add_parser("health", help="检查服务状态")
    commands.add_parser("meta", help="读取账户、分类和配置")
    listing = commands.add_parser("list", help="查询账单")
    listing.add_argument("--month", help="YYYY-MM")
    listing.add_argument("--q", "--query", dest="q", help="搜索文字")
    listing.add_argument("--account")
    listing.add_argument("--category")
    listing.add_argument("--type", choices=ENTRY_TYPES + ("refund",))
    listing.add_argument("--limit", type=int, default=100, help="每页 1–500 条，默认 100")
    listing.add_argument("--offset", type=int, default=0, help="跳过条数；按 next_offset 继续分页")
    summary = commands.add_parser("summary", help="按月统计；省略月份由服务选择")
    summary.add_argument("--month", help="YYYY-MM")
    addition = commands.add_parser("add", help="添加收入、支出或转账")
    add_payload_options(addition)
    refund = commands.add_parser("refund", help="为指定账单添加退款")
    refund.add_argument("id", help="原始账单 ID")
    add_payload_options(refund, refund=True)
    edit = commands.add_parser("edit", help="修改指定账单")
    edit.add_argument("id", help="账单 ID")
    edit.add_argument("--expected-version", type=int, help="先 get 原单读取 version；JSON 可提供 expected_version")
    add_payload_options(edit, editing=True)
    for command, help_text in (("delete", "软删除指定账单"), ("restore", "恢复软删除账单")):
        sub = commands.add_parser(command, help=help_text)
        sub.add_argument("id", help="账单 ID")
        sub.add_argument("--expected-version", type=int, required=True, help="先 get 原单读取 version")
    upload = commands.add_parser("upload", help="上传最多 8 MB 的小票文件")
    upload.add_argument("file", help="本地小票路径")
    for command, help_text in (("export", "导出完整 JSON"), ("backup", "保存共享完整备份 ZIP（管理员权限）")):
        sub = commands.add_parser(command, help=help_text)
        sub.add_argument("--output", required=True, help="输出文件路径")
        sub.add_argument("--overwrite", action="store_true", help="明确允许覆盖现有输出文件")
    return parser


def main(argv=None):
    global _ACTIVE_CONNECTION, _CONFIG_PATH
    args = build_parser().parse_args(argv)
    _ACTIVE_CONNECTION = None
    _CONFIG_PATH = args.config
    try:
        result = execute(args)
        print(json.dumps(redact_token(result, _ACTIVE_CONNECTION.token if _ACTIVE_CONNECTION else os.environ.get("LEDGER_TOKEN")),
                         ensure_ascii=False, allow_nan=False))
        return 0
    except (LedgerError, ValueError, TypeError) as exc:
        # JSON stderr allows callers to parse failures without scraping prose.
        message = str(exc)
        token = _ACTIVE_CONNECTION.token if _ACTIVE_CONNECTION else os.environ.get("LEDGER_TOKEN")
        if token:
            message = message.replace(token, "[redacted]")
        failure = {"ok": False, "error": message}
        if isinstance(exc, LedgerError) and exc.details:
            failure.update(exc.details, message=message, status=exc.status)
        print(json.dumps(redact_token(failure, token), ensure_ascii=False), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(json.dumps({"ok": False, "error": "已取消。"}, ensure_ascii=False), file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
