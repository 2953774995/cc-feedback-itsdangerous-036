#!/usr/bin/env python3
"""验收探针：多代密钥轮换与重放防护（10 条契约）。

在未实现 `itsdangerous.rotate` 的基线上，10 条全部 FAIL。
"""
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))  # 老版本仓库把包放在 src/ 下

RESULTS = []


def probe(name):
    def deco(fn):
        try:
            fn()
        except AssertionError as exc:
            RESULTS.append((name, False, str(exc) or "断言失败"))
        except Exception as exc:
            RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        else:
            RESULTS.append((name, True, ""))
        return fn

    return deco


def rotate():
    import itsdangerous.rotate as m  # noqa: F401

    return m


SALT = "download-link"


def ring():
    m = rotate()
    return m.KeyRing([("k1", b"secret-one-0123456789"), ("k2", b"secret-two-0123456789")])


@probe("P01 密钥环构造与当前代")
def p01():
    m = rotate()
    r = ring()
    assert r.current[0] == "k2", f"current 应为最后一代 k2，实际 {r.current[0]}"
    assert len(r.keys) == 2, f"应有两代密钥，实际 {len(r.keys)}"
    try:
        m.KeyRing([])
    except ValueError:
        pass
    else:
        raise AssertionError("空密钥环应抛 ValueError")


@probe("P02 签发只用当前代且能往返")
def p02():
    r = ring()
    tok = r.sign("payload-a", SALT)
    payload, kid = r.verify(tok, SALT)
    assert payload == "payload-a", f"往返值不对：{payload}"
    assert kid == "k2", f"应标记当前代 k2，实际 {kid}"


@probe("P03 签名错仍是 BadSignature")
def p03():
    from itsdangerous.exc import BadSignature

    r = ring()
    tok = r.sign("payload-b", SALT)
    tampered = tok[:-4] + ("aaaa" if tok[-4:] != "aaaa" else "bbbb")
    try:
        r.verify(tampered, SALT)
    except BadSignature:
        pass
    except Exception as exc:
        raise AssertionError(f"签名错应抛 BadSignature，实际 {type(exc).__name__}")
    else:
        raise AssertionError("篡改后的令牌不该验通")


@probe("P04 旧代令牌 promote 后仍可验")
def p04():
    r = ring()
    old_tok = r.sign("legacy", SALT)  # 当前是 k2
    r.promote(b"secret-three-0123456789", "k3")
    payload, kid = r.verify(old_tok, SALT)
    assert payload == "legacy" and kid == "k2", f"旧代应仍可验且 key_id=k2，实际 {payload}/{kid}"
    new_tok = r.sign("fresh", SALT)
    payload2, kid2 = r.verify(new_tok, SALT)
    assert kid2 == "k3", f"promote 后签发应为 k3，实际 {kid2}"


@probe("P05 退役代与未知代分类")
def p05():
    r = ring()
    retired_tok = r.sign("will-retire", SALT)
    kid = r.verify(retired_tok, SALT)[1]
    r.retire(kid)
    try:
        r.verify(retired_tok, SALT)
    except Exception as exc:
        assert "retire" in type(exc).__name__.lower() or "retired" in str(exc).lower(), \
            f"退役代异常语义不对：{type(exc).__name__}: {exc}"
    else:
        raise AssertionError("退役代令牌不该验通")
    try:
        r.verify("garbage-token-without-keyid", SALT)
    except Exception:
        pass
    else:
        raise AssertionError("无法识别 key_id 的令牌应抛异常")


@probe("P06 批量入口与部分失败隔离")
def p06():
    m = rotate()
    r = ring()
    good = [r.sign(f"v{i}", SALT) for i in range(3)]
    values = [good[0], "not-a-token", good[1], "", good[2]]
    out = m.verify_many(values, SALT, ring=r) if "ring" in m.verify_many.__code__.co_varnames else r.verify_many(values, SALT)
    assert len(out.items) == 5, f"应返回 5 条，实际 {len(out.items)}"
    reasons = [i.reason for i in out.items]
    assert reasons[1] == "malformed" and reasons[3] == "malformed", f"坏令牌应为 malformed，实际 {reasons}"
    assert reasons[0] == reasons[2] == reasons[4] == "ok", f"好令牌应为 ok，实际 {reasons}"


@probe("P07 max_age 过期判定")
def p07():
    r = ring()
    tok = r.sign("aging", SALT)
    out = r.verify_many([tok], SALT, max_age=1)
    time.sleep(1.2)
    out2 = r.verify_many([tok], SALT, max_age=1)
    assert out2.items[0].reason == "expired", f"超龄应为 expired，实际 {out2.items[0].reason}"
    out3 = r.verify_many([tok], SALT, max_age=None)
    assert out3.items[0].reason == "ok", f"max_age=None 不应判过期，实际 {out3.items[0].reason}"


@probe("P08 重放台账生效")
def p08():
    class Store:
        def __init__(self):
            self.seen_set = set()

        def seen(self, nonce):
            return nonce in self.seen_set

        def mark(self, nonce):
            self.seen_set.add(nonce)

    r = ring()
    store = Store()
    tok = r.sign("nonce-payload", SALT, nonce="n-001")
    first = r.verify_many([tok], SALT, nonce_store=store)
    assert first.items[0].reason == "ok", f"首次应为 ok，实际 {first.items[0].reason}"
    assert store.seen("n-001"), "ok 条目必须调用 mark"
    second = r.verify_many([tok], SALT, nonce_store=store)
    assert second.items[0].reason == "replay", f"二次应为 replay，实际 {second.items[0].reason}"


@probe("P09 统计口径与空输入")
def p09():
    r = ring()
    good = r.sign("s1", SALT)
    bad = good[:-3] + "xyz"
    out = r.verify_many([good, bad, "junk"], SALT)
    st = out.stats
    assert st["ok"] == 1 and st["bad"] == 2, f"ok/bad 计数不对：{st}"
    assert st["by_reason"].get("bad_signature") == 1, f"by_reason 不对：{st['by_reason']}"
    assert st["by_key_id"].get("k2") == 1, f"by_key_id 不对：{st['by_key_id']}"
    empty = r.verify_many([], SALT)
    assert empty.items == [] and empty.stats["ok"] == 0, "空输入应返回空结构"


@probe("P10 万级性能与既有 Signer 不回归")
def p10():
    from itsdangerous import Signer

    r = ring()
    values = [r.sign(f"v{i}", SALT) for i in range(10000)]
    t0 = time.perf_counter()
    out = r.verify_many(values, SALT)
    cost = time.perf_counter() - t0
    assert out.stats["ok"] == 10000, f"万条应全部通过，实际 {out.stats['ok']}"
    assert cost < 2.0, f"万条校验耗时 {cost:.2f}s 超过 2s"
    s = Signer(b"plain-secret")
    assert s.unsign(s.sign("abc")) == b"abc", "既有 Signer 往返被破坏"


def main():
    print("=" * 60)
    print("验收探针：多代密钥轮换与重放防护（10 条契约）")
    print("=" * 60)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    for name, ok, detail in RESULTS:
        print(f"PASS  {name}" if ok else f"FAIL  {name}\n      {detail}")
    print("-" * 60)
    print(f"探针结果：{passed}/{len(RESULTS)} 通过")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
