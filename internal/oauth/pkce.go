package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

var (
	ErrInvalidCodeChallenge       = errors.New("invalid code challenge")
	ErrUnsupportedChallengeMethod = errors.New("unsupported code challenge method")
	ErrCodeVerificationFailed     = errors.New("code verification failed")
)

// ValidateCodeChallenge validates the PKCE code challenge parameters
func ValidateCodeChallenge(codeChallenge, codeChallengeMethod string) error {
	if codeChallenge == "" {
		return fmt.Errorf("%w: code_challenge is required", ErrInvalidCodeChallenge)
	}

	if codeChallengeMethod == "" {
		return fmt.Errorf("%w: code_challenge_method is required", ErrInvalidCodeChallenge)
	}

	// We support both plain and S256 methods
	if codeChallengeMethod != "plain" && codeChallengeMethod != "S256" {
		return fmt.Errorf("%w: %s", ErrUnsupportedChallengeMethod, codeChallengeMethod)
	}

	// For S256, code challenge should be base64url encoded
	if codeChallengeMethod == "S256" {
		if len(codeChallenge) < 43 || len(codeChallenge) > 128 {
			return fmt.Errorf("%w: invalid code_challenge length for S256", ErrInvalidCodeChallenge)
		}
	}

	// For plain, code verifier requirements apply
	if codeChallengeMethod == "plain" {
		if len(codeChallenge) < 43 || len(codeChallenge) > 128 {
			return fmt.Errorf("%w: invalid code_challenge length for plain", ErrInvalidCodeChallenge)
		}
	}

	return nil
}

// VerifyCodeChallenge verifies the code verifier against the stored code challenge
func VerifyCodeChallenge(codeVerifier, codeChallenge, codeChallengeMethod string) error {
	if codeVerifier == "" {
		return fmt.Errorf("%w: code_verifier is required", ErrCodeVerificationFailed)
	}

	// Verify code verifier length (43-128 characters)
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		return fmt.Errorf("%w: invalid code_verifier length", ErrCodeVerificationFailed)
	}

	switch codeChallengeMethod {
	case "plain":
		if codeVerifier != codeChallenge {
			return ErrCodeVerificationFailed
		}
	case "S256":
		// Generate SHA256 hash of code verifier and base64url encode it
		hash := sha256.Sum256([]byte(codeVerifier))
		computed := base64.RawURLEncoding.EncodeToString(hash[:])

		if computed != codeChallenge {
			return ErrCodeVerificationFailed
		}
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedChallengeMethod, codeChallengeMethod)
	}

	return nil
}
