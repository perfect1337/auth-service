CREATE IF NOT EXIST INDEX idx_refresh_tokens_token ON refresh_tokens(token);
CREATE IF NOT EXIST INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);