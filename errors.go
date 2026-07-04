package onepassword

import (
	"encoding/json"
	"errors"
)

type DesktopSessionExpiredError struct {
	message string
}

func (e *DesktopSessionExpiredError) Error() string {
	return e.message
}

type RateLimitExceededError struct {
	message string
}

func (e *RateLimitExceededError) Error() string {
	return e.message
}

// Error is a categorized error returned by the SDK. Name identifies the error
// category (for example "NotFound", "PermissionDenied", or "Conflict") so
// callers can branch on it with errors.As.
type Error struct {
	Name    string
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

func unmarshalError(err string) error {
	v := struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	}{}
	if e := json.Unmarshal([]byte(err), &v); e != nil || v.Message == "" {
		return errors.New(err)
	}
	switch v.Name {
	case "DesktopSessionExpired":
		return &DesktopSessionExpiredError{
			message: v.Message,
		}
	case "RateLimitExceeded":
		return &RateLimitExceededError{
			message: v.Message,
		}
	case "":
		return errors.New(v.Message)
	default:
		return &Error{Name: v.Name, Message: v.Message}
	}
}
