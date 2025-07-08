-- Migration: Add account_type column to users table
ALTER TABLE users ADD COLUMN account_type TEXT DEFAULT 'user';
-- Optionally, set admin for the admin user
UPDATE users SET account_type = 'admin' WHERE username = 'admin';
