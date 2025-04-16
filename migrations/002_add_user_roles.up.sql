-- Создаем тип для ролей
CREATE TYPE user_role AS ENUM ('user', 'admin', 'moderator');

-- Меняем тип колонки role
ALTER TABLE users 
ALTER COLUMN role TYPE user_role USING role::user_role;

-- Устанавливаем значение по умолчанию
ALTER TABLE users 
ALTER COLUMN role SET DEFAULT 'user';