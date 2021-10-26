CREATE TABLE IF NOT EXISTS authentication_logs (
    id SERIAL,
    time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    successful BOOLEAN NOT NULL,
    username VARCHAR(100) NOT NULL,
    auth_type VARCHAR(3) NOT NULL DEFAULT '1FA',
    remote_ip VARCHAR(47) NULL DEFAULT NULL,
    request_uri TEXT,
    request_method VARCHAR(4) NOT NULL DEFAULT '',
    PRIMARY KEY (id)
);

CREATE INDEX authentication_logs_username_idx ON authentication_logs (time, username, auth_type);
CREATE INDEX authentication_logs_remote_ip_idx ON authentication_logs (time, remote_ip, auth_type);

CREATE TABLE IF NOT EXISTS identity_verification_tokens (
    id SERIAL,
    created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expired TIMESTAMP WITH TIME ZONE NULL DEFAULT NULL,
    jti VARCHAR(36) NOT NULL,
    exp TIMESTAMP WITH TIME ZONE NOT NULL,
    username VARCHAR(100) NOT NULL,
    action VARCHAR(32),
    remote_ip VARCHAR(47) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (jti)
);

CREATE TABLE IF NOT EXISTS migrations (
    id SERIAL,
    time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    prior INTEGER NULL DEFAULT NULL,
    current INTEGER NOT NULL,
    version VARCHAR(64) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS totp_configurations (
    id SERIAL,
    username VARCHAR(100) NOT NULL,
    algorithm VARCHAR(6) NOT NULL DEFAULT 'SHA1',
    digits INTEGER NOT NULL DEFAULT 6,
    totp_period INTEGER NOT NULL DEFAULT 30,
    secret VARCHAR(64) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (username)
);

CREATE TABLE IF NOT EXISTS u2f_devices (
    id SERIAL,
    username VARCHAR(100) NOT NULL,
    description VARCHAR(30) NOT NULL DEFAULT 'Primary',
    key_handle BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (username, description)
);

CREATE TABLE IF NOT EXISTS user_preferences (
    id SERIAL,
    username VARCHAR(100) NOT NULL,
    second_factor_method VARCHAR(11) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (username)
);