-- Migration to add vulnerable fields to users table
-- VULNERABILITY: Storing plaintext passwords (CWE-256, CWE-312)

ALTER TABLE users ADD COLUMN IF NOT EXISTS plaintext_password VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'user';
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS api_key VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS secret_question VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS secret_answer VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS ssn VARCHAR(11);
ALTER TABLE users ADD COLUMN IF NOT EXISTS credit_card VARCHAR(20);
ALTER TABLE users ADD COLUMN IF NOT EXISTS cvv VARCHAR(4);

-- Create admin user with hardcoded credentials (VULNERABILITY: CWE-798)
INSERT INTO users (name, email, encrypted_password, plaintext_password, role, is_admin)
VALUES ('Administrator', 'admin@example.com', 'admin123', 'admin123', 'admin', TRUE)
ON CONFLICT (email) DO NOTHING;

-- Create test user with known credentials (VULNERABILITY: CWE-798)
INSERT INTO users (name, email, encrypted_password, plaintext_password, role, is_admin)
VALUES ('Test User', 'test@example.com', 'password123', 'password123', 'user', FALSE)
ON CONFLICT (email) DO NOTHING;
