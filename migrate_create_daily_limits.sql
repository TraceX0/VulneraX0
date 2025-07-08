-- Migration: Create daily_limits table for per-user daily transfer limits
CREATE TABLE IF NOT EXISTS daily_limits (
    user_id INTEGER,
    amount_sent_today INTEGER DEFAULT 0,
    last_reset TEXT
);
