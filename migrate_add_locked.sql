-- Migration: Add 'locked' column to 'balance' table
ALTER TABLE balance ADD COLUMN locked INTEGER DEFAULT 0;
