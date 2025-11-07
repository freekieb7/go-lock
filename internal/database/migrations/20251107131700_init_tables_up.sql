CREATE TABLE tbl_account (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    type TEXT NOT NULL, -- 'user', 'client' or 'system'
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_account_type ON tbl_account(type);
CREATE INDEX idx_account_created_at ON tbl_account(created_at);

CREATE TABLE tbl_user (
    id UUID NOT NULL REFERENCES tbl_account(id) ON DELETE CASCADE,
    type TEXT NOT NULL, -- 'user' or 'admin'
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id),
    UNIQUE(email)
);

CREATE INDEX idx_user_created_at ON tbl_user(created_at);

CREATE TABLE tbl_client (
    id UUID NOT NULL REFERENCES tbl_account(id) ON DELETE CASCADE,
    public_id TEXT NOT NULL,
    secret TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    is_confidential BOOLEAN NOT NULL,
    logo_uri TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id)
);

CREATE INDEX idx_client_public_id ON tbl_client(public_id);
CREATE INDEX idx_client_name ON tbl_client(name);
CREATE INDEX idx_client_created_at ON tbl_client(created_at);

CREATE TABLE tbl_resource_server (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    url TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id),
    UNIQUE(url)
);

CREATE INDEX idx_resource_server_created_at ON tbl_resource_server(created_at);

CREATE TABLE tbl_scope (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    resource_server_id UUID REFERENCES tbl_resource_server(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id),
    UNIQUE(resource_server_id, name)
);

CREATE INDEX idx_scope_resource_server_id ON tbl_scope(resource_server_id);
CREATE INDEX idx_scope_created_at ON tbl_scope(created_at);

CREATE TABLE tbl_permission (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    account_id UUID NOT NULL REFERENCES tbl_account(id) ON DELETE CASCADE,
    scope_id UUID NOT NULL REFERENCES tbl_scope(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(account_id, scope_id)
);

CREATE INDEX idx_permission_account_id ON tbl_permission(account_id);
CREATE INDEX idx_permission_scope_id ON tbl_permission(scope_id);
CREATE INDEX idx_permission_created_at ON tbl_permission(created_at);

CREATE TABLE tbl_access_token (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    token TEXT NOT NULL,
    client_id UUID NOT NULL REFERENCES tbl_client(id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES tbl_account(id) ON DELETE CASCADE,
    scopes TEXT[] NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(token)
);

CREATE INDEX idx_access_token_token ON tbl_access_token(token);
CREATE INDEX idx_access_token_account_id ON tbl_access_token(account_id);
CREATE INDEX idx_access_token_client_id ON tbl_access_token(client_id);
CREATE INDEX idx_access_token_expires_at_created ON tbl_access_token(expires_at, created_at);
CREATE INDEX idx_access_token_created_at ON tbl_access_token(created_at);

CREATE TABLE tbl_authorization_code (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    code TEXT NOT NULL,
    client_id UUID NOT NULL REFERENCES tbl_client(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
    scopes TEXT[] NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(code)
);

CREATE INDEX idx_authorization_code_code ON tbl_authorization_code(code);
CREATE INDEX idx_authorization_code_client_id ON tbl_authorization_code(client_id);
CREATE INDEX idx_authorization_code_user_id ON tbl_authorization_code(user_id);
CREATE INDEX idx_authorization_code_expires_at ON tbl_authorization_code(expires_at);

CREATE TABLE tbl_session (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    token TEXT NOT NULL,
    user_id UUID REFERENCES tbl_user(id) ON DELETE CASCADE,
    data JSONB NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(token)
);

CREATE INDEX idx_session_user_id ON tbl_session(user_id);
CREATE INDEX idx_session_expires_at_user ON tbl_session(expires_at, user_id);
CREATE INDEX idx_session_created_at ON tbl_session(created_at);

CREATE TABLE tbl_granted_scope (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
    client_id UUID NOT NULL REFERENCES tbl_client(id) ON DELETE CASCADE,
    scope_id UUID NOT NULL REFERENCES tbl_scope(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_granted_scope_user_id ON tbl_granted_scope(user_id);
CREATE INDEX idx_granted_scope_client_id ON tbl_granted_scope(client_id);
CREATE INDEX idx_granted_scope_created_at ON tbl_granted_scope(created_at);

CREATE TABLE tbl_refresh_token (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    token TEXT NOT NULL,
    client_id UUID NOT NULL REFERENCES tbl_client(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
    scopes TEXT[] NOT NULL,
    chain_id UUID NOT NULL, -- Links related refresh tokens in a rotation chain
    parent_token_id UUID REFERENCES tbl_refresh_token(id) ON DELETE SET NULL, -- Previous token in the chain
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE, -- Tracks if token has been used/revoked
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    used_at TIMESTAMP NULL, -- When the token was used for refresh
    UNIQUE(token)
);

CREATE INDEX idx_refresh_token_token ON tbl_refresh_token(token);
CREATE INDEX idx_refresh_token_client_id ON tbl_refresh_token(client_id);
CREATE INDEX idx_refresh_token_user_id ON tbl_refresh_token(user_id);
CREATE INDEX idx_refresh_token_chain_id ON tbl_refresh_token(chain_id);
CREATE INDEX idx_refresh_token_parent_token_id ON tbl_refresh_token(parent_token_id);
CREATE INDEX idx_refresh_token_expires_at ON tbl_refresh_token(expires_at);
CREATE INDEX idx_refresh_token_created_at ON tbl_refresh_token(created_at);
CREATE INDEX idx_refresh_token_is_revoked ON tbl_refresh_token(is_revoked);

INSERT INTO tbl_scope (name, description)
VALUES 
    ('offline_access', 'Allows the application to obtain refresh tokens for long-term access'), 
    ('openid', 'Allows the application to authenticate the user and obtain their identity information'),
    ('email', 'Allows the application to access the user''s email address');
