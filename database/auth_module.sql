-- ============================================================
-- Auth Module migration
-- Apply on top of the base users table.
-- Engine: InnoDB, Charset: utf8mb4
-- ============================================================

-- 1. Extend users table with TOTP columns
ALTER TABLE users
    ADD COLUMN totp_secret  VARCHAR(64)   NULL DEFAULT NULL AFTER password_hash,
    ADD COLUMN totp_enabled TINYINT(1)    NOT NULL DEFAULT 0 AFTER totp_secret;

-- 2. Refresh tokens (with rotation/revocation)
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id     INT UNSIGNED    NOT NULL,
    jti         CHAR(32)        NOT NULL,
    expires_at  DATETIME        NOT NULL,
    revoked_at  DATETIME        NULL DEFAULT NULL,
    created_at  DATETIME        NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_jti (jti),
    KEY idx_user_active (user_id, revoked_at, expires_at),
    CONSTRAINT fk_refresh_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. JWT blacklist (revoked access tokens)
CREATE TABLE IF NOT EXISTS jwt_blacklist (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    jti         CHAR(32)        NOT NULL,
    expires_at  DATETIME        NOT NULL,
    created_at  DATETIME        NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_blk_jti (jti),
    KEY idx_blk_exp (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Magic links (passwordless email login)
CREATE TABLE IF NOT EXISTS magic_links (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id     INT UNSIGNED    NOT NULL,
    token_hash  CHAR(64)        NOT NULL,
    expires_at  DATETIME        NOT NULL,
    used_at     DATETIME        NULL DEFAULT NULL,
    ip_hash     CHAR(64)        NOT NULL,
    created_at  DATETIME        NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_mlink_hash (token_hash),
    KEY idx_mlink_user (user_id),
    KEY idx_mlink_exp (expires_at),
    CONSTRAINT fk_mlink_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
