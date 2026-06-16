-- ============================================================
-- Auth Module v2 - security hardening migration.
-- Apply AFTER auth_module.sql.
--
-- Aggiunge `token_version` alla tabella users. Il valore viene
-- embedded nel claim 'tv' degli access token. BaseController::requireJwt
-- confronta il claim col valore in DB: un bump invalida istantaneamente
-- tutti gli access token vivi del singolo utente (multi-device).
--
-- Bumped automaticamente da:
--   * AuthController::logout                 (logout esplicito)
--   * AuthController::refresh (reuse path)   (token-theft response)
-- Bumpa manualmente con UserModel::bumpTokenVersion() anche su:
--   * cambio password
--   * disabilitazione account
--   * eventi di sicurezza
-- ============================================================

ALTER TABLE users
    ADD COLUMN token_version INT UNSIGNED NOT NULL DEFAULT 1
    AFTER totp_enabled;
