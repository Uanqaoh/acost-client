"""Private client settings and credential-safe HTTP transport (standard library)."""
from dataclasses import dataclass
import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request


class ClientError(Exception):
    def __init__(self, message, status=None, *, details=None):
        super().__init__(message)
        self.status = status
        self.details = details


def duplicate_conflict_details(body, token):
    """Expose only the duplicate review contract, never arbitrary error fields."""
    if not isinstance(body, dict) or body.get("error") != "possible_duplicate":
        return None

    def safe_text(value):
        return value.replace(token, "[redacted]") if token else value

    result = {"error": "possible_duplicate", "candidates": []}
    fields = {"id", "date", "time", "type", "amount_cents", "account", "merchant",
              "reason", "currency", "version"}
    candidates = body.get("candidates")
    if not isinstance(candidates, list):
        return None
    for candidate in candidates:
        if not isinstance(candidate, dict) or not isinstance(candidate.get("id"), str):
            return None
        result["candidates"].append({key: safe_text(value) if isinstance(value, str) else value
                                     for key, value in candidate.items()
                                     if key in fields and (value is None or isinstance(value, (str, int)))})
    acknowledged = body.get("duplicate_acknowledgements")
    if not isinstance(acknowledged, list) or any(not isinstance(value, str) for value in acknowledged):
        return None
    result["duplicate_acknowledgements"] = [safe_text(value) for value in acknowledged]
    if isinstance(body.get("candidate_count"), int) and not isinstance(body["candidate_count"], bool):
        result["candidate_count"] = body["candidate_count"]
    if isinstance(body.get("candidates_truncated"), bool):
        result["candidates_truncated"] = body["candidates_truncated"]
    return result


def config_directories():
    """New installs use Acost. An existing Qiao Ledger file stays in place."""
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
        return [base / "Acost", base / "Qiao Ledger"]
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return [base / "acost", base / "qiao-ledger"]


def default_config(client):
    filename = client + ".json"
    current, legacy = config_directories()
    existing = legacy / filename
    if existing.is_file():
        return existing
    return current / filename


def validate_url(value, mode="shared"):
    try:
        parts = urllib.parse.urlsplit(value)
        port = parts.port
    except (ValueError, TypeError):
        raise ClientError("服务地址无效。") from None
    if (not isinstance(value, str) or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.query or parts.fragment
            or parts.path not in ("", "/", "/functions/v1/ledger") or any(ord(c) < 33 for c in value)
            or (port is not None and not 1 <= port <= 65535)):
        raise ClientError("服务地址仅允许 HTTPS 根地址或 /functions/v1/ledger，不能含凭据或查询。")
    if mode not in {"shared", "local"}:
        raise ClientError("连接模式必须为 shared 或 local。")
    if mode == "shared" and parts.scheme != "https":
        raise ClientError("共享模式必须使用 HTTPS；不会回退到本地账本。")
    if mode == "local" and (parts.scheme != "http" or parts.hostname != "127.0.0.1" or parts.path not in ("", "/")):
        raise ClientError("隔离开发模式只允许明确的 http://127.0.0.1:端口 地址。")
    return value.rstrip("/")


def validate_token(token, required=True):
    if (not isinstance(token, str) or (required and not token) or len(token) > 4096
            or any(ord(c) < 33 or ord(c) > 126 for c in token)):
        raise ClientError("访问凭据为空或格式无效，请重新配置。")
    return token


class Keychain:
    """Use Security.framework directly: the secret never enters process arguments."""
    service = "com.qiao-ledger.client"

    def __init__(self):
        if sys.platform != "darwin":
            raise OSError("Keychain unavailable")
        self.cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        self.sec = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        ptr, number = ctypes.c_void_p, ctypes.c_long
        self.cf.CFStringCreateWithCString.argtypes = [ptr, ctypes.c_char_p, ctypes.c_uint32]
        self.cf.CFStringCreateWithCString.restype = ptr
        self.cf.CFDictionaryCreate.argtypes = [ptr, ctypes.POINTER(ptr), ctypes.POINTER(ptr), number, ptr, ptr]
        self.cf.CFDictionaryCreate.restype = ptr
        self.cf.CFDataCreate.argtypes = [ptr, ptr, number]
        self.cf.CFDataCreate.restype = ptr
        self.cf.CFDataGetLength.argtypes = [ptr]
        self.cf.CFDataGetLength.restype = number
        self.cf.CFDataGetBytePtr.argtypes = [ptr]
        self.cf.CFDataGetBytePtr.restype = ptr
        self.cf.CFRelease.argtypes = [ptr]
        self.sec.SecItemAdd.argtypes = [ptr, ptr]
        self.sec.SecItemUpdate.argtypes = [ptr, ptr]
        self.sec.SecItemCopyMatching.argtypes = [ptr, ctypes.POINTER(ptr)]
        self.owned = []

    def constant(self, name):
        return ctypes.c_void_p.in_dll(self.sec, name).value

    def string(self, value):
        item = self.cf.CFStringCreateWithCString(None, value.encode(), 0x08000100)
        self.owned.append(item)
        return item

    def dictionary(self, values):
        ptr = ctypes.c_void_p
        keys, vals = (ptr * len(values))(*values.keys()), (ptr * len(values))(*values.values())
        # Pass addresses of the exported callback structs, not their first fields.
        key_callbacks = ctypes.addressof(ctypes.c_byte.in_dll(self.cf, "kCFTypeDictionaryKeyCallBacks"))
        value_callbacks = ctypes.addressof(ctypes.c_byte.in_dll(self.cf, "kCFTypeDictionaryValueCallBacks"))
        item = self.cf.CFDictionaryCreate(None, keys, vals, len(values), key_callbacks, value_callbacks)
        self.owned.append(item)
        return item

    def query(self, account):
        return {self.constant("kSecClass"): self.constant("kSecClassGenericPassword"),
                self.constant("kSecAttrService"): self.string(self.service),
                self.constant("kSecAttrAccount"): self.string(account)}

    def close(self):
        for item in reversed(self.owned):
            if item:
                self.cf.CFRelease(item)
        self.owned.clear()

    def set(self, account, token):
        try:
            query = self.query(account)
            encoded = token.encode()
            data = self.cf.CFDataCreate(None, ctypes.c_char_p(encoded), len(encoded))
            self.owned.append(data)
            values = {self.constant("kSecValueData"): data}
            status = self.sec.SecItemUpdate(self.dictionary(query), self.dictionary(values))
            if status == -25300:  # errSecItemNotFound
                status = self.sec.SecItemAdd(self.dictionary(query | values), None)
            if status != 0:
                raise OSError("Keychain save failed")
        finally:
            self.close()

    def get(self, account):
        result = ctypes.c_void_p()
        try:
            query = self.query(account)
            query[self.constant("kSecReturnData")] = ctypes.c_void_p.in_dll(self.cf, "kCFBooleanTrue").value
            query[self.constant("kSecMatchLimit")] = self.constant("kSecMatchLimitOne")
            if self.sec.SecItemCopyMatching(self.dictionary(query), ctypes.byref(result)) != 0:
                raise OSError("Keychain read failed")
            raw = ctypes.string_at(self.cf.CFDataGetBytePtr(result), self.cf.CFDataGetLength(result))
            return raw.decode()
        finally:
            if result.value:
                self.cf.CFRelease(result)
            self.close()


def _private_json(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
                raise ClientError("连接配置必须属于当前用户，且权限为 600。")
            value = json.load(stream)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except FileNotFoundError:
        return None
    except ClientError:
        raise
    except (OSError, ValueError, UnicodeError):
        raise ClientError("无法安全读取连接配置，请重新配置。") from None


def save_connection(path, url, token, *, mode="shared", use_keychain=True):
    path = Path(path).expanduser()
    url = validate_url(url, mode)
    validate_token(token, required=True)
    config = {"mode": mode, "url": url, "credential_storage": "file"}
    if use_keychain and sys.platform == "darwin":
        account = hashlib.sha256(str(path.resolve()).encode()).hexdigest()
        try:
            Keychain().set(account, token)
            config.update(credential_storage="keychain", keychain_account=account)
        except (OSError, AttributeError):
            config["token"] = token
    else:
        config["token"] = token
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ClientError("配置路径不能是符号链接。")
    temp = None
    try:
        descriptor, temp = tempfile.mkstemp(prefix=".connection-", dir=path.parent)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(config, output, ensure_ascii=False)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
    except OSError:
        raise ClientError("无法保存私有连接配置。") from None
    finally:
        if temp and os.path.exists(temp):
            os.unlink(temp)
    return config["credential_storage"]


def load_connection(path, *, environ=None, allow_environment=True):
    environment = os.environ if environ is None else environ
    has_url_override = allow_environment and "LEDGER_URL" in environment
    config = {} if has_url_override else (_private_json(Path(path).expanduser()) or {})
    if has_url_override:
        # An overridden URL may never inherit a saved credential for another server.
        config = {"url": environment.get("LEDGER_URL"), "token": environment.get("LEDGER_TOKEN", ""),
                  "mode": environment.get("LEDGER_MODE", "shared"), "credential_storage": "file"}
    elif allow_environment:
        if "LEDGER_TOKEN" in environment:
            config.update(token=environment["LEDGER_TOKEN"], credential_storage="file")
        if "LEDGER_MODE" in environment:
            config["mode"] = environment["LEDGER_MODE"]
    if not config.get("url"):
        raise ClientError("尚未配置共享服务地址；请先运行 configure。不会连接或创建本地账本。")
    mode = config.get("mode", "shared")
    url = validate_url(config["url"], mode)
    token = config.get("token", "")
    if config.get("credential_storage") == "keychain":
        try:
            token = Keychain().get(config["keychain_account"])
        except (OSError, KeyError, AttributeError):
            raise ClientError("无法从钥匙串读取访问凭据，请重新配置。") from None
    validate_token(token, required=mode == "shared")
    return Connection(url, token, mode)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class Connection:
    url: str
    token: str
    mode: str = "shared"

    def __post_init__(self):
        self.url = validate_url(self.url, self.mode)
        validate_token(self.token, required=self.mode == "shared")

    def request(self, method, path, *, payload=None, query=None, max_bytes=16 * 1024 * 1024):
        if not re_safe_route(path):
            raise ClientError("请求路径无效。")
        target = self.url + path
        if query:
            target += "?" + urllib.parse.urlencode(query)
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json; charset=utf-8"
            data = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode()
        request = urllib.request.Request(target, data=data, headers=headers, method=method)
        # Redirects must never forward credentials. Ignore ambient proxy settings,
        # especially for loopback demo traffic; TLS still uses system CA checking.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        try:
            with opener.open(request, timeout=20) as response:
                raw = response.read(max_bytes + 1)
                if len(raw) > max_bytes:
                    raise ClientError("服务响应超出允许大小。", 502)
                return raw, response.headers.get_content_type()
        except urllib.error.HTTPError as exc:
            status = exc.code
            if 300 <= status < 400:
                raise ClientError("服务返回重定向，已拒绝转发凭据；请配置最终 HTTPS 地址。", 502) from None
            body = None
            try:
                body = json.loads(exc.read(65536).decode())
                message = body.get("message", "请求失败") if isinstance(body, dict) else "请求失败"
            except (ValueError, UnicodeError, OSError):
                message = "请求失败"
            message = str(message)
            if self.token:
                message = message.replace(self.token, "[redacted]")
            details = duplicate_conflict_details(body, self.token) if status == 409 else None
            raise ClientError("HTTP " + str(status) + "：" + message[:1000], status, details=details) from None
        except (urllib.error.URLError, OSError, TimeoutError):
            raise ClientError("无法连接共享账本。请检查网络与服务状态；不会切换到本地账本。", 503) from None


def re_safe_route(path):
    # Callers supply only absolute API paths; disallow URL syntax and traversal.
    if not isinstance(path, str) or not path.startswith("/api/") or any(c in path for c in "?#\\\r\n"):
        return False
    decoded = urllib.parse.unquote(path)
    return ".." not in decoded.split("/") and "\x00" not in decoded and "\\" not in decoded
