-- Rollback migration
ALTER TABLE users DROP COLUMN IF EXISTS plaintext_password;
ALTER TABLE users DROP COLUMN IF EXISTS role;
ALTER TABLE users DROP COLUMN IF EXISTS is_admin;
ALTER TABLE users DROP COLUMN IF EXISTS reset_token;
ALTER TABLE users DROP COLUMN IF EXISTS api_key;
ALTER TABLE users DROP COLUMN IF EXISTS secret_question;
ALTER TABLE users DROP COLUMN IF EXISTS secret_answer;
ALTER TABLE users DROP COLUMN IF EXISTS ssn;
ALTER TABLE users DROP COLUMN IF EXISTS credit_card;
ALTER TABLE users DROP COLUMN IF EXISTS cvv;

DELETE FROM users WHERE email IN ('admin@example.com', 'test@example.com');
