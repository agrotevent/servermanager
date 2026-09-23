from servermanager import security


def test_encrypt_roundtrip(data_dir):
    token = security.encrypt("geheim äöü")
    assert token and "geheim" not in token
    assert security.decrypt(token) == "geheim äöü"
    assert security.encrypt("") is None
    assert security.decrypt(None) == ""


def test_password_hashing():
    h = security.hash_password("Sehr-Geheim-123")
    assert security.verify_password(h, "Sehr-Geheim-123")
    assert not security.verify_password(h, "falsch")
    assert not security.verify_password("kaputt", "x")


def test_password_policy():
    assert security.password_problems("kurz")
    assert security.password_problems("nurkleinbuchstaben")
    assert not security.password_problems("Gutes-Passwort1")
    assert not security.password_problems(security.random_password())


def test_totp():
    import pyotp
    secret = security.new_totp_secret()
    assert security.verify_totp(secret, pyotp.TOTP(secret).now())
    assert not security.verify_totp(secret, "000000x")
    assert not security.verify_totp(secret, "")


def test_token_hash_is_stable():
    t = security.new_token()
    assert security.token_hash(t) == security.token_hash(t)
    assert security.const_eq("a", "a") and not security.const_eq("a", "b")
