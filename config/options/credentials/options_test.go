package credentials

import (
	"testing"
)

func TestNew(t *testing.T) {
	creds := New()

	if creds.Application != "" {
		t.Errorf("expected Application to be empty, got %s", creds.Application)
	}
	if creds.ClientID != "" {
		t.Errorf("expected ClientID to be empty, got %s", creds.ClientID)
	}
	if creds.ClientSecret != "" {
		t.Errorf("expected ClientSecret to be empty, got %s", creds.ClientSecret)
	}
}

func TestWithApplication(t *testing.T) {
	application := "test-app"
	creds := New(WithApplication(application))

	if creds.Application != application {
		t.Errorf("expected Application to be %s, got %s", application, creds.Application)
	}
}

func TestWithClientID(t *testing.T) {
	clientID := "test-client-id"
	creds := New(WithClientID(clientID))

	if creds.ClientID != clientID {
		t.Errorf("expected ClientID to be %s, got %s", clientID, creds.ClientID)
	}
}

func TestWithClientSecret(t *testing.T) {
	clientSecret := "test-client-secret"
	creds := New(WithClientSecret(clientSecret))

	if creds.ClientSecret != clientSecret {
		t.Errorf("expected ClientSecret to be %s, got %s", clientSecret, creds.ClientSecret)
	}
}

func TestCompleteConfiguration(t *testing.T) {
	application := "my-app"
	clientID := "my-client-id"
	clientSecret := "my-client-secret"

	creds := New(
		WithApplication(application),
		WithClientID(clientID),
		WithClientSecret(clientSecret),
	)

	if creds.Application != application {
		t.Errorf("expected Application to be %s, got %s", application, creds.Application)
	}
	if creds.ClientID != clientID {
		t.Errorf("expected ClientID to be %s, got %s", clientID, creds.ClientID)
	}
	if creds.ClientSecret != clientSecret {
		t.Errorf("expected ClientSecret to be %s, got %s", clientSecret, creds.ClientSecret)
	}
}

func TestValidateWithPublicClient(t *testing.T) {
	creds := New(
		WithApplication("test-app"),
		WithClientID("test-client"),
	)

	if err := creds.Validate(true); err != nil {
		t.Errorf("expected validation to pass for public client, got error: %v", err)
	}
}

func TestValidateWithConfidentialClient(t *testing.T) {
	creds := New(
		WithApplication("test-app"),
		WithClientID("test-client"),
		WithClientSecret("test-secret"),
	)

	if err := creds.Validate(false); err != nil {
		t.Errorf("expected validation to pass for confidential client, got error: %v", err)
	}
}

func TestValidateWithMissingClientSecret(t *testing.T) {
	creds := New(
		WithApplication("test-app"),
		WithClientID("test-client"),
	)

	if err := creds.Validate(false); err == nil {
		t.Errorf("expected validation to fail for confidential client without secret")
	}
}

func TestValidateWithMissingApplication(t *testing.T) {
	creds := New(
		WithClientID("test-client"),
		WithClientSecret("test-secret"),
	)

	if err := creds.Validate(false); err == nil {
		t.Errorf("expected validation to fail without application name")
	}
}

func TestValidateWithMissingClientID(t *testing.T) {
	creds := New(
		WithApplication("test-app"),
		WithClientSecret("test-secret"),
	)

	if err := creds.Validate(false); err == nil {
		t.Errorf("expected validation to fail without client ID")
	}
}
