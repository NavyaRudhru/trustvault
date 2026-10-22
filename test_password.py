from app.security import hash_password, verify_password


def test_password_hash_and_verify():
    password = "TrustVault-Test-2026!"
    password_hash = hash_password(password)

    assert password_hash != password
    assert verify_password(password, password_hash)
    assert not verify_password("Wrong-Password-2026!", password_hash)


def test_short_password_is_rejected():
    try:
        hash_password("short")
        assert False, "Expected short password to be rejected"
    except ValueError:
        pass