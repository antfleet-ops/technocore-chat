"""Run: uv run --group dev python -m pytest tests"""

import _client
import pytest
from _client import _keypair, _multibase

client = _client.client  # the shared TestClient fixture


def test_a_did_key_has_exactly_one_spelling(client):
    """Ownership compares DID *strings*: `_note_write_gate` asks `signer != current`, and
    `_allowed_keys` matches by string. So a key with more than one accepted spelling is a
    key whose owner the service cannot recognise — the caller signs with the same private
    key, presents an alias, and fails its own allow-list.

    Each of the three shapes below decodes to a real key's bytes and is refused only by
    the *other* half of a two-part check. `or` → `and` short-circuits on the common
    operand and silently deletes that half, which is why all three need pinning
    separately rather than as one "malformed DID" case.
    """
    import didkey

    did, _ = _keypair()
    mb = did[len(didkey.PREFIX) :]
    real = didkey.public_key(did)

    # Right suffix, wrong prefix — same length, so only the `startswith` check refuses it.
    alias = "XXXXXXXX" + mb
    # Right prefix and leading `z`, one base58 zero-digit too long. Base58 ignores the
    # padding, so it decodes to the same 34 bytes; only the exact-length check refuses it.
    padded = didkey.PREFIX + "z1" + mb[1:]
    # Right prefix and right length, but the multicodec says something other than
    # ed25519-pub. Only the codec check refuses it.
    wrong_codec = didkey.PREFIX + "z" + _multibase(b"\xe7\x01" + real)
    assert len(wrong_codec) == len(did), "premise: this must pass the length check to matter"

    for spelling in (alias, padded, wrong_codec):
        with pytest.raises(didkey.DidError):
            didkey.public_key(spelling)
        assert not didkey.is_did(spelling)

    assert didkey.public_key(did) == real  # …and the canonical one still works


def test_a_signature_has_exactly_one_spelling():
    """A signature is an integrity token, so it must have exactly one accepted spelling.

    An 86-char base64url signature carries four slack bits in its final character, so
    sixteen strings decode to the same 64-byte Ed25519 signature and all of them verify.
    #177: accept only the canonical re-encode, so a captured signed URL cannot be replayed
    under any of its fifteen aliases. servers never store the signature (§5.4) and the
    only signer emits the canonical form, so this refuses only the slack variants.
    """
    import base64
    import didkey

    # The exact urlsafe alphabet order base64.urlsafe_b64{en,de}code uses.
    B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    index = {c: i for i, c in enumerate(B64URL)}

    did, sign = _keypair()
    message = "lobby|1|hello"
    sig = sign(message)  # canonical 86-char base64url
    assert len(sig) == didkey.SIG_CHARS

    # The canonical signature verifies.
    didkey.verify(did, sig, message)

    # Build a slack spelling: keep the top two bits of the final base64url character, vary
    # its four slack bits to a value that differs. Sixteen spellings share the same bytes;
    # pick any one that is not the canonical character.
    last = sig[-1]
    v = index[last]
    top2 = (v >> 4) & 0x3
    slack_bits = (v & 0xF) ^ 0x1  # guaranteed to differ from the canonical low four bits
    slack = sig[:-1] + B64URL[(top2 << 4) | slack_bits]
    assert slack != sig
    # Sanity: the slack spelling decodes to the same 64 bytes the canonical one does.
    dec = base64.urlsafe_b64decode(slack + "==")[:64]
    assert dec == base64.urlsafe_b64decode(sig + "==")[:64]

    # Before the fix this raised nothing; after it must be refused as non-canonical.
    with pytest.raises(didkey.DidError):
        didkey.verify(did, slack, message)

    # Mirror: the signer (scripts/sign.py) emits the canonical form, so a freshly signed
    # string re-encodes to itself — the verifier and the signer cannot drift here.
    raw = base64.urlsafe_b64decode(sig + "==")[:64]
    assert base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == sig
