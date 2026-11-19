"""审计日志写入器：并发安全的追加、脱敏、哈希链与重放去重。

磁盘格式
--------
每次追加产生一条 UTF-8 JSON 行（以 ``\\n`` 结尾），外层对象为::

    {"hash": "<64 位十六进制 HMAC>", "line": "<payload 的紧凑 JSON>"}

``payload`` 是哈希链实际覆盖的单行 JSON，字段固定为::

    {"prev_hash": "<上一条 hash；创世为空串>", "record": {...},
     "seq": 1, "ts": 1750000000.0}

``hash = HMAC-SHA256(key, prev_hash_bytes + line.encode("utf-8"))``。
每个日志文件旁有 ``<path>.head``（``HEAD_SUFFIX``）头锚点，内容为
``"<行数> <最后一条 hash>\\n"``；它让 ``verify_chain`` 能发现末尾整行被删除。

除 pytest 外只使用 Python 标准库。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from typing import Any

# 单条 JSON 编码后的硬上限。append 写盘前也必须检查。
MAX_BYTES = 256 * 1024

# 尾锚点文件后缀，与日志文件放在同一目录。
HEAD_SUFFIX = ".head"


class AuditError(Exception):
    """审计日志的编码、链校验或时间检查失败。"""


# ---------------------------------------------------------------------------
# 内部工具
# ---------------------------------------------------------------------------


def _escape_strings(obj: Any) -> Any:
    """递归把字符串（键与值）里的裸 CR/LF 替换为两字符字面量 ``\\r``/``\\n``。

    替换发生在 JSON 编码之前，因此值内换行不可能在磁盘上伪造出额外的物理
    日志行。dict 与 list 会重建为新容器，不修改入参。
    """
    if isinstance(obj, str):
        return obj.replace("\r", "\\r").replace("\n", "\\n")
    if isinstance(obj, dict):
        return {
            (_escape_strings(key) if isinstance(key, str) else key):
                _escape_strings(value)
            for key, value in obj.items()
        }
    if isinstance(obj, list):
        return [_escape_strings(item) for item in obj]
    return obj


def _canonical_bytes(obj: Any) -> bytes:
    """规范化编码：ensure_ascii=False、键排序、紧凑分隔符，输出 UTF-8 字节。"""
    return json.dumps(
        _escape_strings(obj),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# encode
# ---------------------------------------------------------------------------


def encode(record: dict) -> bytes:
    """把 ``record`` 编码成无尾随换行的单行 UTF-8 JSON 字节串。

    编码规则：

    * ``ensure_ascii=False``、键排序、分隔符为 ``("," , ":")``；
    * 递归地把字符串值（以及字符串键）里的 CR、LF 替换成两个字面量字符
      ``\\r``、``\\n``，再交给 JSON 编码，避免值内换行伪造出日志行；
    * 输出中不得出现裸 CR 或 LF；
    * UTF-8 字节数超过 ``MAX_BYTES`` 时抛 :class:`AuditError`。

    非 JSON 可序列化对象可抛 ``TypeError``；尺寸问题必须抛 ``AuditError``。
    """
    data = _canonical_bytes(record)
    if len(data) > MAX_BYTES:
        raise AuditError(
            f"编码后 {len(data)} 字节超过单条上限 {MAX_BYTES} 字节"
        )
    return data


# ---------------------------------------------------------------------------
# redact
# ---------------------------------------------------------------------------


def _compile_pattern(pattern: str) -> tuple[tuple[str, ...], bool]:
    """把规则模式预编译为 (casefold 路径段元组, 是否为带点的锚定路径)。"""
    return tuple(part.casefold() for part in pattern.split(".")), "." in pattern


def _rule_matches(
    compiled: tuple[tuple[str, ...], bool],
    path: tuple[str, ...],
    segment: str,
) -> bool:
    """判断当前键（``segment``，位于 ``path`` 之下）是否命中规则。

    ``*`` 段只匹配单个路径段；无点模式在任意深度匹配同名键。
    """
    segments, dotted = compiled
    if dotted:
        target = path + (segment,)
        if len(target) != len(segments):
            return False
        return all(
            pat == "*" or pat == part
            for pat, part in zip(segments, target)
        )
    pat = segments[0]
    return pat == "*" or pat == segment


def _redact_walk(
    obj: Any,
    path: tuple[str, ...],
    deny_rules: list[tuple[tuple[str, ...], bool]],
    redact_rules: list[tuple[tuple[str, ...], bool]],
) -> Any:
    if isinstance(obj, dict):
        result: dict = {}
        for key, value in obj.items():
            if isinstance(key, str):
                segment = key.casefold()
                # deny 优先于 redact：命中即整条删除。
                if any(
                    _rule_matches(rule, path, segment) for rule in deny_rules
                ):
                    continue
                if any(
                    _rule_matches(rule, path, segment) for rule in redact_rules
                ):
                    result[key] = "***"
                    continue
                result[key] = _redact_walk(
                    value, path + (segment,), deny_rules, redact_rules
                )
            else:
                # 非字符串键不参与模式匹配，原样保留键，值继续递归重建。
                result[key] = _redact_walk(
                    value, path, deny_rules, redact_rules
                )
        return result
    if isinstance(obj, list):
        # list 下标不是路径段，元素在相同路径下递归。
        return [
            _redact_walk(item, path, deny_rules, redact_rules) for item in obj
        ]
    return obj


def redact(record: dict, rules: dict) -> dict:
    """返回深层脱敏后的新对象，绝不修改 ``record`` 或其嵌套容器。

    ``rules`` 支持两个可选列表：

    * ``redact_keys``：命中的键，其值整体替换为 ``"***"``。
    * ``deny_keys``：命中的键连同值整条删除。

    匹配规则（大小写不敏感，按 Unicode casefold 比较）：

    * 不含点号（``.``）的模式匹配任意深度的同名键，如 ``password``；
    * 含点号的模式匹配从根开始的完整路径，如 ``user.password``；
    * ``*`` 只匹配一个路径段，如 ``user.*`` 匹配 ``user.card`` 但不匹配
      ``user.card.number``。

    dict 与 list 都要递归遍历；``deny_keys`` 优先于 ``redact_keys``。
    非字符串键按原对象保留，不参与模式匹配。
    """
    deny_rules = [
        _compile_pattern(pattern)
        for pattern in rules.get("deny_keys", [])
        if isinstance(pattern, str)
    ]
    redact_rules = [
        _compile_pattern(pattern)
        for pattern in rules.get("redact_keys", [])
        if isinstance(pattern, str)
    ]
    return _redact_walk(record, (), deny_rules, redact_rules)


# ---------------------------------------------------------------------------
# append：逐路径锁 + 单次 O_APPEND 整行写 + HMAC 哈希链
# ---------------------------------------------------------------------------

_locks_guard = threading.Lock()
_path_locks: dict[str, threading.Lock] = {}


def _path_lock(path: str) -> threading.Lock:
    """返回按绝对路径区分的串行锁，保证同一路径的 append 完全串行。"""
    absolute = os.path.abspath(path)
    with _locks_guard:
        lock = _path_locks.get(absolute)
        if lock is None:
            lock = threading.Lock()
            _path_locks[absolute] = lock
        return lock


def _read_tail_state(
    path: str,
) -> tuple[bytes, int, Any]:
    """读取当前尾锚状态：(上一条 hash 原始字节, 最后 seq, 最后 ts)。

    空文件或文件不存在时返回 ``(b"", 0, None)``（创世状态）。
    """
    if not os.path.exists(path):
        return b"", 0, None
    with open(path, "rb") as handle:
        data = handle.read()
    if not data:
        return b"", 0, None
    wrapper = json.loads(data.splitlines()[-1].decode("utf-8"))
    payload = json.loads(wrapper["line"])
    return bytes.fromhex(wrapper["hash"]), int(payload["seq"]), payload["ts"]


def _atomic_write_head(head_path: str, seq: int, digest: str) -> None:
    """先写同目录临时文件再 os.replace，保证 head 锚点原子更新。"""
    tmp_path = head_path + ".tmp"
    payload = f"{seq} {digest}\n".encode("utf-8")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    os.replace(tmp_path, head_path)


def append(path: str, record: dict, key: bytes, now: float) -> dict:
    """原子追加一条记录并返回 ``{"seq": int, "hash": str, "line": str}``。

    契约：

    * ``seq`` 从 1 开始连续递增，由逐路径锁串行分配；
    * ``prev_hash`` 从当前文件最后一条成功写入的记录读取，空文件时为空字节；
      哈希链输入使用该十六进制字段解码后的原始 32 字节，创世为空字节串；
    * 磁盘上的整条 JSON 行加 ``\\n`` 必须通过一次带 ``O_APPEND`` 的
      ``os.write`` 写入，不能拆成多次 write，也不允许先 seek 再写；
    * ``hash`` 为 HMAC-SHA256 的 64 位小写十六进制；
    * ``line`` 是哈希覆盖的 payload 单行 JSON，磁盘行是带 ``hash`` 的包装对象；
    * ``now`` 必须不小于上一条记录的 ``ts``，否则抛 :class:`AuditError`；
    * 记录编码后超过 ``MAX_BYTES`` 抛 :class:`AuditError`；
    * 成功写日志行后原子更新 ``<path>.head`` 为 ``"<seq> <hash>\\n"``；
    * 并发调用时不得出现行交错、重复 seq 或损坏的 head。

    实现应复用 :func:`encode` 的转义与尺寸规则；``record`` 本身不被修改。
    """
    lock = _path_lock(path)
    with lock:
        # 写盘前的尺寸/可序列化检查；不修改 record。
        encode(record)

        prev_hash, last_seq, last_ts = _read_tail_state(path)

        # 单调不减校验必须发生在任何写盘之前，失败时日志保持原样。
        if last_ts is not None and now < last_ts:
            raise AuditError(
                f"时间戳回拨：now={now!r} 小于上一条记录 ts={last_ts!r}"
            )

        seq = last_seq + 1
        payload = {
            "prev_hash": prev_hash.hex(),
            "record": record,
            "seq": seq,
            "ts": now,
        }
        line_bytes = _canonical_bytes(payload)
        line = line_bytes.decode("utf-8")

        digest = hmac.new(
            key, prev_hash + line_bytes, hashlib.sha256
        ).hexdigest()

        chunk = _canonical_bytes({"hash": digest, "line": line}) + b"\n"

        # 一次 os.open + 一次 os.write：O_APPEND 保证整行原子追加到末尾，
        # 不 seek、不分多次 write，从根本上消除行交错与半行。
        fd = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
        )
        try:
            os.write(fd, chunk)
        finally:
            os.close(fd)

        _atomic_write_head(path + HEAD_SUFFIX, seq, digest)

        return {"seq": seq, "hash": digest, "line": line}


# ---------------------------------------------------------------------------
# verify_chain
# ---------------------------------------------------------------------------


def verify_chain(path: str, key: bytes) -> int:
    """校验整条日志链并返回记录行数。

    依次检查：

    * 每一条物理行都是合法 JSON，且包装结构和 payload 结构完整；
    * HMAC 使用 ``prev_hash_bytes + line.encode("utf-8")`` 重算并常量时间比较；
    * ``prev_hash`` 与上一条 ``hash`` 相等，创世记录为空串；
    * ``seq`` 从 1 开始严格连续；
    * ``ts`` 单调不减（相等允许）；
    * 日志文件以换行结束，且 ``<path>.head`` 的行数与最后 hash 和文件一致，
      从而拒绝末尾整行删除。

    任一条件不满足抛 :class:`AuditError`；空日志返回 0。校验过程中不得写入
    或修复日志文件。
    """
    head_path = path + HEAD_SUFFIX
    try:
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except FileNotFoundError:
            data = b""

        if not data:
            # 空日志：允许没有 head；head 若存在则必须声称行数为 0。
            if os.path.exists(head_path):
                with open(head_path, "rb") as handle:
                    parts = handle.read().split()
                if len(parts) != 2 or int(parts[0]) != 0:
                    raise AuditError("空日志与 head 锚点不一致")
            return 0

        if not data.endswith(b"\n"):
            raise AuditError("日志文件未以换行符结束，末行可能被截断")

        prev_hash = b""
        expected_seq = 1
        last_ts: Any = None
        last_hash = ""
        count = 0

        for raw in data.splitlines():
            wrapper = json.loads(raw.decode("utf-8"))
            if not isinstance(wrapper, dict) or set(wrapper) != {"hash", "line"}:
                raise AuditError("包装对象结构不完整")
            line = wrapper["line"]
            if not isinstance(line, str):
                raise AuditError("line 字段必须为字符串")

            payload = json.loads(line)
            if not isinstance(payload, dict) or set(payload) != {
                "prev_hash",
                "record",
                "seq",
                "ts",
            }:
                raise AuditError("payload 结构不完整")

            expected_digest = hmac.new(
                key, prev_hash + line.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(expected_digest, wrapper["hash"]):
                raise AuditError(f"第 {expected_seq} 条记录 HMAC 校验失败")

            if payload["prev_hash"] != prev_hash.hex():
                raise AuditError(f"第 {expected_seq} 条记录 prev_hash 断链")
            if payload["seq"] != expected_seq:
                raise AuditError(
                    f"seq 不连续：期望 {expected_seq}，实际 {payload['seq']!r}"
                )

            ts = payload["ts"]
            if last_ts is not None and ts < last_ts:
                raise AuditError(f"第 {expected_seq} 条记录 ts 非单调不减")

            prev_hash = bytes.fromhex(wrapper["hash"])
            last_hash = wrapper["hash"]
            last_ts = ts
            expected_seq += 1
            count += 1

        # head 锚点：行数与最后 hash 必须与文件一致，挡住末尾整行删除。
        with open(head_path, "rb") as handle:
            head_parts = handle.read().split()
        if (
            len(head_parts) != 2
            or int(head_parts[0]) != count
            or head_parts[1] != last_hash.encode("utf-8")
        ):
            raise AuditError("head 锚点与日志文件不一致")

        return count

    except AuditError:
        raise
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # JSON 解析失败、hex 解码失败、字段缺失、类型错误等统一为 AuditError。
        raise AuditError(f"链校验失败：{exc}") from exc


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------


def replay(records: list[dict], now: float, window: int = 300) -> list[dict]:
    """按时间窗口过滤并去重重放请求，返回新列表。

    先丢弃满足 ``now - ts > window`` 的记录（``ts`` 取 ``record["ts"]``）；
    恰好等于窗口边界的记录保留。然后在剩余记录中，对相同的
    ``(actor, action, target)`` 三元组只保留输入顺序中的第一条。未来时间戳
    （``ts > now``）不因本窗口规则被丢弃。

    输出保持输入相对顺序，不修改输入记录或列表。``window`` 为负数时没有
    记录能通过窗口检查。
    """
    if window < 0:
        return []

    seen: set[tuple[Any, Any, Any]] = set()
    result: list[dict] = []

    for record in records:
        ts = record["ts"]
        # 未来时间戳不受窗口规则影响；其余记录在边界（含相等）之内保留。
        if ts <= now and now - ts > window:
            continue

        fingerprint = (
            record["actor"],
            record["action"],
            record["target"],
        )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        result.append(record)

    return result
