import io

import pytest

from servermanager.backup import BackupError, decrypt_stream, encrypt_stream


def roundtrip(data: bytes, pw="pass-phrase"):
    enc = io.BytesIO()
    encrypt_stream(io.BytesIO(data), enc, pw)
    out = io.BytesIO()
    decrypt_stream(io.BytesIO(enc.getvalue()), out, pw)
    return enc.getvalue(), out.getvalue()


@pytest.mark.parametrize("size", [0, 10, (1 << 20) - 1, 1 << 20, (1 << 20) * 2 + 5])
def test_roundtrip_sizes(size):
    data = bytes(i % 251 for i in range(size))
    enc, dec = roundtrip(data)
    assert dec == data
    assert data[:50] not in enc[30:] or size < 50


def test_wrong_passphrase():
    enc, _ = roundtrip(b"secret data")
    with pytest.raises(BackupError):
        decrypt_stream(io.BytesIO(enc), io.BytesIO(), "falsch")


def test_truncation_detected():
    data = b"x" * ((1 << 20) + 100)
    enc, _ = roundtrip(data)
    # cut off the final chunk
    cut = enc[: len(enc) - 120]
    with pytest.raises(BackupError):
        decrypt_stream(io.BytesIO(cut), io.BytesIO(), "pass-phrase")


def test_full_backup_cycle(db, data_dir):
    from servermanager import backup
    path = backup.create_backup(db, note="test", passphrase="abc-123")
    assert path.name.endswith(".enc")
    manifest = backup.inspect_backup(path, "abc-123")
    assert manifest["note"] == "test"
    with pytest.raises(BackupError):
        backup.inspect_backup(path, "nope")
    staging = backup.stage_restore(path, "abc-123")
    assert (staging / "servermanager.db").exists() and (staging / "secret.key").exists()
    plain = backup.create_backup(db, note="plain", passphrase="")
    assert backup.inspect_backup(plain)["note"] == "plain"
    assert any(b["name"] == plain.name for b in backup.list_backups())
    with pytest.raises(BackupError):
        backup.backup_path("../../etc/passwd")
