CREATE OR REPLACE FUNCTION clean_old_chat_messages()
RETURNS TRIGGER AS $$
BEGIN
    DELETE FROM chat_messages WHERE created_at < NOW() - INTERVAL '30 minutes';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_clean_old_chat_messages
AFTER INSERT ON chat_messages
EXECUTE FUNCTION clean_old_chat_messages();