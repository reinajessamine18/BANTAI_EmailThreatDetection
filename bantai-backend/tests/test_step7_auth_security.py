from app.api.auth_security import hash_password, verify_password, new_token, token_hash

def test_password_hash_verifies_and_is_salted():
    first = hash_password("Correct horse battery staple!")
    second = hash_password("Correct horse battery staple!")
    assert first != second
    assert verify_password("Correct horse battery staple!", first)
    assert not verify_password("wrong password", first)

def test_tokens_are_random_and_only_hash_is_persisted():
    first, second = new_token(), new_token()
    assert first != second
    assert token_hash(first) != first
    assert len(token_hash(first)) == 64
