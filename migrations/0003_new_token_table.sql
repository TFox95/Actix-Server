
CREATE TABLE IF NOT EXISTS new_tokens (
    token_key VARCHAR(255) NOT NULL,
    iat INTEGER NOT NULL,
    exp INTEGER NOT NULL,
    ref_usernames VARCHAR(25) NOT NULL
)
