-- Возвращаем обратно текстовый тип
ALTER TABLE users 
ALTER COLUMN role TYPE VARCHAR(20);

-- Удаляем тип
DROP TYPE IF EXISTS user_role;