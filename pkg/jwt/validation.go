package jwt

import (
	"time"
)

// ValidationOptions contains options for JWT token validation
type ValidationOptions struct {
	ValidateIssuer     bool
	ValidateAudience   bool
	ValidateExpiration bool
	ValidateNotBefore  bool
	ValidateIssuedAt   bool
	ValidateSubject    bool

	ExpectedIssuer   string
	ExpectedAudience string
	ExpectedSubject  string
	TimeFunc         func() time.Time
	Leeway           time.Duration
}

// DefaultValidationOptions returns default validation options
func DefaultValidationOptions() ValidationOptions {
	return ValidationOptions{
		ValidateExpiration: true,
		ValidateNotBefore:  true,
		ValidateIssuedAt:   true,
		TimeFunc:           time.Now,
		Leeway:             0,
	}
}

// ValidateToken validates a JWT token according to the provided options
func ValidateToken(token Token, options ValidationOptions) error {
	now := options.TimeFunc()

	if options.ValidateExpiration {
		if err := validateExpiration(token, now, options.Leeway); err != nil {
			return err
		}
	}

	if options.ValidateNotBefore {
		if err := validateNotBefore(token, now, options.Leeway); err != nil {
			return err
		}
	}

	if options.ValidateIssuedAt {
		if err := validateIssuedAt(token, now, options.Leeway); err != nil {
			return err
		}
	}

	if options.ValidateIssuer && options.ExpectedIssuer != "" {
		if err := validateIssuer(token, options.ExpectedIssuer); err != nil {
			return err
		}
	}

	if options.ValidateAudience && options.ExpectedAudience != "" {
		if err := validateAudience(token, options.ExpectedAudience); err != nil {
			return err
		}
	}

	if options.ValidateSubject && options.ExpectedSubject != "" {
		if err := validateSubject(token, options.ExpectedSubject); err != nil {
			return err
		}
	}

	return nil
}

// validateExpiration validates the exp claim
func validateExpiration(token Token, now time.Time, leeway time.Duration) error {
	exp, ok := token.Payload["exp"]
	if !ok {
		return ErrTokenRequiredClaimMissing
	}

	expTime, err := getTimeFromClaim(exp)
	if err != nil {
		return err
	}

	if now.After(expTime.Add(leeway)) {
		return ErrTokenExpired
	}

	return nil
}

// validateNotBefore validates the nbf claim
func validateNotBefore(token Token, now time.Time, leeway time.Duration) error {
	nbf, ok := token.Payload["nbf"]
	if !ok {
		return nil // nbf is optional
	}

	nbfTime, err := getTimeFromClaim(nbf)
	if err != nil {
		return err
	}

	if now.Before(nbfTime.Add(-leeway)) {
		return ErrTokenNotValidYet
	}

	return nil
}

// validateIssuedAt validates the iat claim
func validateIssuedAt(token Token, now time.Time, leeway time.Duration) error {
	iat, ok := token.Payload["iat"]
	if !ok {
		return nil // iat is optional
	}

	iatTime, err := getTimeFromClaim(iat)
	if err != nil {
		return err
	}

	if now.Before(iatTime.Add(-leeway)) {
		return ErrTokenUsedBeforeIssued
	}

	return nil
}

// validateIssuer validates the iss claim
func validateIssuer(token Token, expectedIssuer string) error {
	iss, ok := token.Payload["iss"]
	if !ok {
		return ErrTokenRequiredClaimMissing
	}

	issuer, ok := iss.(string)
	if !ok {
		return ErrInvalidType
	}

	if issuer != expectedIssuer {
		return ErrTokenInvalidIssuer
	}

	return nil
}

// validateAudience validates the aud claim
func validateAudience(token Token, expectedAudience string) error {
	aud, ok := token.Payload["aud"]
	if !ok {
		return ErrTokenRequiredClaimMissing
	}

	// aud can be a string or []string
	switch audience := aud.(type) {
	case string:
		if audience != expectedAudience {
			return ErrTokenInvalidAudience
		}
	case []string:
		found := false
		for _, a := range audience {
			if a == expectedAudience {
				found = true
				break
			}
		}
		if !found {
			return ErrTokenInvalidAudience
		}
	case []interface{}:
		found := false
		for _, a := range audience {
			if str, ok := a.(string); ok && str == expectedAudience {
				found = true
				break
			}
		}
		if !found {
			return ErrTokenInvalidAudience
		}
	default:
		return ErrInvalidType
	}

	return nil
}

// validateSubject validates the sub claim
func validateSubject(token Token, expectedSubject string) error {
	sub, ok := token.Payload["sub"]
	if !ok {
		return ErrTokenRequiredClaimMissing
	}

	subject, ok := sub.(string)
	if !ok {
		return ErrInvalidType
	}

	if subject != expectedSubject {
		return ErrTokenInvalidSubject
	}

	return nil
}

// getTimeFromClaim converts a claim value to time.Time
func getTimeFromClaim(claim interface{}) (time.Time, error) {
	switch v := claim.(type) {
	case float64:
		return time.Unix(int64(v), 0), nil
	case int64:
		return time.Unix(v, 0), nil
	case int:
		return time.Unix(int64(v), 0), nil
	default:
		return time.Time{}, ErrInvalidType
	}
}
