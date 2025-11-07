-- Migration to add JWKS (JSON Web Key Set) table for OpenID Connect support
CREATE TABLE tbl_jwks (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    kid TEXT NOT NULL UNIQUE, -- Key ID for identification in JWT headers
    kty TEXT NOT NULL DEFAULT 'RSA', -- Key type (RSA, EC, etc.)
    use_sig TEXT NOT NULL DEFAULT 'sig', -- Key usage (sig for signature, enc for encryption)
    alg TEXT NOT NULL DEFAULT 'RS256', -- Algorithm (RS256, RS384, RS512, etc.)
    
    -- RSA specific fields
    n TEXT NOT NULL, -- Base64url encoded RSA modulus
    e TEXT NOT NULL, -- Base64url encoded RSA exponent
    
    -- Private key material (PEM encoded, stored securely)
    private_key_pem TEXT NOT NULL, -- PEM encoded private key for signing
    public_key_pem TEXT NOT NULL, -- PEM encoded public key for verification
    
    -- Key lifecycle management
    is_active BOOLEAN NOT NULL DEFAULT TRUE, -- Whether this key is actively used for signing
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP, -- Optional expiration for key rotation
    revoked_at TIMESTAMP -- Track key revocation for security incidents
);

-- Indexes for performance and key management
CREATE INDEX idx_jwks_kid ON tbl_jwks(kid);
CREATE INDEX idx_jwks_active ON tbl_jwks(is_active) WHERE is_active = true;
CREATE INDEX idx_jwks_created_at ON tbl_jwks(created_at);
CREATE INDEX idx_jwks_expires_at ON tbl_jwks(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_jwks_use_alg ON tbl_jwks(use_sig, alg);

-- Ensure we always have at least one active signing key
CREATE UNIQUE INDEX idx_jwks_active_signing ON tbl_jwks(use_sig, is_active) 
WHERE is_active = true AND use_sig = 'sig';

-- Add comments for documentation
COMMENT ON TABLE tbl_jwks IS 'JSON Web Key Set storage for OpenID Connect token signing and verification';
COMMENT ON COLUMN tbl_jwks.kid IS 'Unique key identifier used in JWT headers';
COMMENT ON COLUMN tbl_jwks.n IS 'Base64url encoded RSA modulus for public key';
COMMENT ON COLUMN tbl_jwks.e IS 'Base64url encoded RSA exponent for public key';
COMMENT ON COLUMN tbl_jwks.is_active IS 'Whether this key is currently used for signing new tokens';