-- Migration: Add session_token column to users table
ALTER TABLE users ADD COLUMN session_token TEXT;
