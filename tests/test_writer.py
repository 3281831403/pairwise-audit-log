import copy
import hashlib
import hmac
import json
import os
import threading

import pytest

import auditlog.writer as writer
from auditlog.writer import (
    HEAD_SUFFIX,
    MAX_BYTES,
    AuditError,
    append,
    encode,
    redact,
    replay,
    verify_chain,
)


KEY = b"audit-test-key"


def _canonical(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _payload(raw):
    wrapper = json.loads(raw.decode("utf-8"))
    assert set(wrapper) == {"hash", "line"}
    payload = json.loads(wrapper["line"])
    assert set(payload) == {"prev_hash", "record", "seq", "ts"}
    return payload


def _payloads(path):
    return [_payload(raw) for raw in path.read_bytes().splitlines()]


def _head_path(path):
    return path.with_name(path.name + HEAD_SUFFIX)


def _write_valid_chain(path, records, timestamps):
    """直接写一条哈希正确、seq 连续的链，用于隔离时间戳乱序缺陷。"""
    prev = b""
    chunks = []
    for index, (record, timestamp) in enumerate(zip(records, timestamps), 1):
        payload = {
            "prev_hash": prev.hex(),
            "record": record,
            "seq": index,
            "ts": timestamp,
        }
        line = _canonical(payload)
        digest = hmac.new(
            KEY,
            prev + line.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        chunks.append(
            _canonical({"hash": digest, "line": line}).encode("utf-8") + b"\n"
        )
        prev = bytes.fromhex(digest)

    path.write_bytes(b"".join(chunks))
    _head_path(path).write_bytes(f"{len(chunks)} {prev.hex()}\n".encode("utf-8"))


# ---------------------------------------------------------------------------
# 缺陷 1：并发追加不是原子写，seq 会重复、行会交错。
# ---------------------------------------------------------------------------


def test_concurrent_appends_keep_200_lines_intact(tmp_path):
    path = tmp_path / "audit.jsonl"
    workers = 8
    per_worker = 25
    barrier = threading.Barrier(workers)
    errors = []
    guard = threading.Lock()

    def worker(worker_id):
        try:
            barrier.wait(timeout=10)
            for index in range(per_worker):
                append(
                    str(path),
                    {
                        "actor": f"worker-{worker_id}",
                        "action": "append",
                        "target": f"item-{index}",
                    },
                    KEY,
                    now=1000.0,
                )
        except BaseException as exc:  # 收集后统一断言，避免线程打印噪声
            with guard:
                errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(worker_id,))
        for worker_id in range(workers)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not any(thread.is_alive() for thread in threads), "append 发生死锁"
    assert errors == [], f"并发 append 抛错: {errors!r}"

    raw_lines = path.read_bytes().splitlines()
    assert len(raw_lines) == workers * per_worker

    # 每一行都必须同时是合法的包装 JSON 和合法的 payload JSON，行未交错。
    payloads = [_payload(raw) for raw in raw_lines]
    assert all(item["record"]["action"] == "append" for item in payloads)
    assert [item["seq"] for item in payloads] == list(range(1, 201))


def test_sequences_are_monotonic_and_unique(tmp_path):
    path = tmp_path / "audit.jsonl"
    returned = [
        append(
            str(path),
            {"actor": "alice", "action": "read", "target": f"doc-{index}"},
            KEY,
            now=500.0 + index,
        )
        for index in range(30)
    ]

    seqs = [item["seq"] for item in returned]
    assert seqs == list(range(1, 31))
    assert len(set(seqs)) == 30
    assert [item["seq"] for item in _payloads(path)] == seqs


def test_long_record_is_written_in_one_complete_write(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    blob = "x" * (MAX_BYTES // 4)
    calls = []
    real_write = os.write

    def tracking_write(fd, data):
        calls.append(len(data))
        return real_write(fd, data)

    monkeypatch.setattr(writer.os, "write", tracking_write)
    written = append(
        str(path),
        {"actor": "alice", "action": "bulk", "target": "doc", "blob": blob},
        KEY,
        now=10.0,
    )

    raw = path.read_bytes()
    assert raw.endswith(b"\n")
    assert raw.count(b"\n") == 1
    assert len(raw) > 1024

    # 头锚点可以另写；被追踪的大块 write 只允许发生一次且覆盖整条日志行。
    large_writes = [size for size in calls if size > 1024]
    assert large_writes == [len(raw)]
    assert json.loads(written["line"])["record"]["blob"] == blob
    assert _payload(raw)["record"]["blob"] == blob


# ---------------------------------------------------------------------------
# 缺陷 2：值里的换行没有转义，一条日志可以伪造出两行。
# ---------------------------------------------------------------------------


def test_encode_escapes_newline_and_carriage_return_values():
    encoded = encode({"message": "first\nsecond\rthird"})

    assert b"\n" not in encoded
    assert b"\r" not in encoded
    parsed = json.loads(encoded.decode("utf-8"))
    assert parsed["message"] == "first\\nsecond\\rthird"


def test_appended_values_never_create_extra_json_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    records = [
        {
            "actor": "alice",
            "action": "write",
            "target": "doc-1",
            "note": "first\nforged=yes",
        },
        {
            "actor": "bob",
            "action": "write",
            "target": "doc-2",
            "note": "second\rforged=yes",
        },
    ]
    for index, record in enumerate(records):
        append(str(path), record, KEY, now=100.0 + index)

    raw = path.read_bytes()
    assert raw.count(b"\n") == 2
    physical_lines = raw.splitlines()
    assert len(physical_lines) == 2
    for line in physical_lines:
        json.loads(line.decode("utf-8"))

    payloads = _payloads(path)
    assert [item["record"]["note"] for item in payloads] == [
        "first\\nforged=yes",
        "second\\rforged=yes",
    ]


# ---------------------------------------------------------------------------
# 缺陷 3：时间戳没有单调校验，时钟回拨 / 乱序可以插入旧事件。
# ---------------------------------------------------------------------------


def test_append_rejects_clock_rollback(tmp_path):
    path = tmp_path / "audit.jsonl"
    append(str(path), {"actor": "a", "action": "x", "target": "1"}, KEY, now=200.0)

    with pytest.raises(AuditError):
        append(
            str(path),
            {"actor": "a", "action": "x", "target": "2"},
            KEY,
            now=199.5,
        )

    assert len(_payloads(path)) == 1
    assert verify_chain(str(path), KEY) == 1


def test_equal_timestamps_are_allowed(tmp_path):
    path = tmp_path / "audit.jsonl"
    append(str(path), {"actor": "a", "action": "x", "target": "1"}, KEY, now=300.0)
    append(str(path), {"actor": "a", "action": "x", "target": "2"}, KEY, now=300.0)

    assert verify_chain(str(path), KEY) == 2


def test_verify_rejects_out_of_order_timestamps(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write_valid_chain(
        path,
        [
            {"actor": "a", "action": "x", "target": "1"},
            {"actor": "a", "action": "x", "target": "2"},
            {"actor": "a", "action": "x", "target": "3"},
        ],
        [100.0, 90.0, 80.0],
    )

    with pytest.raises(AuditError):
        verify_chain(str(path), KEY)


# ---------------------------------------------------------------------------
# 缺陷 4：脱敏只处理顶层精确键名，嵌套对象和大小写变体漏掉。
# ---------------------------------------------------------------------------


def test_redact_masks_nested_keys():
    original = {
        "password": "top",
        "user": {
            "password": "nested",
            "profile": {"password": "deep", "display": "alice"},
        },
        "items": [{"password": "in-list", "name": "one"}],
        "visible": "keep",
    }
    before = copy.deepcopy(original)

    result = redact(original, {"redact_keys": ["password"], "deny_keys": []})

    assert result["password"] == "***"
    assert result["user"]["password"] == "***"
    assert result["user"]["profile"]["password"] == "***"
    assert result["user"]["profile"]["display"] == "alice"
    assert result["items"][0]["password"] == "***"
    assert result["items"][0]["name"] == "one"
    assert result["visible"] == "keep"
    assert original == before
    assert result is not original
    assert result["user"] is not original["user"]
    assert result["items"][0] is not original["items"][0]


def test_redact_is_case_insensitive():
    original = {
        "PASSWORD": "top",
        "user": {"PaSsWoRd": "nested", "name": "alice"},
    }
    before = copy.deepcopy(original)

    result = redact(original, {"redact_keys": ["passWord"], "deny_keys": []})

    assert result["PASSWORD"] == "***"
    assert result["user"]["PaSsWoRd"] == "***"
    assert result["user"]["name"] == "alice"
    assert original == before


def test_redact_supports_dot_paths_wildcards_and_deny():
    original = {
        "user": {
            "card": {"number": "4111111111111111", "cvc": "123"},
            "name": "Alice",
        },
        "card": {"number": "outer-visible"},
    }
    before = copy.deepcopy(original)

    result = redact(
        original,
        {
            "redact_keys": ["user.card.*", "USER.NAME"],
            "deny_keys": ["user.card.CVC"],
        },
    )

    assert result["user"]["card"] == {"number": "***"}
    assert result["user"]["name"] == "***"
    assert result["card"]["number"] == "outer-visible"
    assert original == before


# ---------------------------------------------------------------------------
# 缺陷 5：没有哈希链和重放窗口，篡改、删尾与重放都发现不了。
# ---------------------------------------------------------------------------


def test_verify_rejects_tampered_middle_line(tmp_path):
    path = tmp_path / "audit.jsonl"
    for index in range(3):
        append(
            str(path),
            {"actor": "alice", "action": "read", "target": f"doc-{index}"},
            KEY,
            now=100.0 + index,
        )

    lines = path.read_bytes().splitlines()
    wrapper = json.loads(lines[1].decode("utf-8"))
    payload = json.loads(wrapper["line"])
    payload["record"]["action"] = "tampered"
    wrapper["line"] = _canonical(payload)
    lines[1] = _canonical(wrapper).encode("utf-8")
    path.write_bytes(b"\n".join(lines) + b"\n")

    with pytest.raises(AuditError):
        verify_chain(str(path), KEY)


def test_verify_rejects_deleted_tail_line(tmp_path):
    path = tmp_path / "audit.jsonl"
    for index in range(3):
        append(
            str(path),
            {"actor": "alice", "action": "read", "target": f"doc-{index}"},
            KEY,
            now=200.0 + index,
        )

    lines = path.read_bytes().splitlines(keepends=True)
    assert len(lines) == 3
    path.write_bytes(b"".join(lines[:-1]))

    with pytest.raises(AuditError):
        verify_chain(str(path), KEY)


def test_replay_deduplicates_within_window():
    records = [
        {"actor": "alice", "action": "read", "target": "doc", "ts": 700.0},
        {"actor": "alice", "action": "read", "target": "doc", "ts": 900.0},
        {"actor": "bob", "action": "read", "target": "doc", "ts": 950.0},
        {"actor": "carol", "action": "read", "target": "doc", "ts": 650.0},
        {"actor": "dave", "action": "read", "target": "doc", "ts": 1000.5},
    ]
    before = copy.deepcopy(records)

    result = replay(records, now=1000.0, window=300)

    assert [(item["actor"], item["action"], item["target"]) for item in result] == [
        ("alice", "read", "doc"),
        ("bob", "read", "doc"),
        ("dave", "read", "doc"),
    ]
    assert result[0]["ts"] == 700.0
    assert records == before


def test_append_then_verify_returns_line_count(tmp_path):
    path = tmp_path / "audit.jsonl"
    for index in range(4):
        written = append(
            str(path),
            {"actor": "alice", "action": "read", "target": f"doc-{index}"},
            KEY,
            now=1000.0 + index,
        )
        assert written["seq"] == index + 1
        assert len(written["hash"]) == 64

    assert verify_chain(str(path), KEY) == 4
