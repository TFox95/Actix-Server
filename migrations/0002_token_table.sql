
CREATE TABLE IF NOT EXISTS tokens (
    token_key TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    user_username VARCHAR(25) REFERENCES users(username)
);
