package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v2"
)

func TestSeedContainerInitialAdminFromEnvMatchesDatabaseSchema(t *testing.T) {
	tmp := t.TempDir()
	origInstallPath := ludusInstallPath
	ludusInstallPath = tmp
	t.Cleanup(func() { ludusInstallPath = origInstallPath })

	if err := os.MkdirAll(filepath.Join(tmp, "install"), 0700); err != nil {
		t.Fatalf("mkdir install: %v", err)
	}

	t.Setenv("LUDUS_ADMIN_USER_ID", "CA")
	t.Setenv("LUDUS_ADMIN_NAME", "Caleb Admin")
	t.Setenv("LUDUS_ADMIN_EMAIL", "")
	t.Setenv("LUDUS_ADMIN_PASSWORD", "SuperSecret123!")
	t.Setenv("LUDUS_ADMIN_PASSWORD_FILE", "")

	if err := seedContainerInitialAdminFromEnv(); err != nil {
		t.Fatalf("seedContainerInitialAdminFromEnv failed: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(tmp, "install", "initial-admin.yml"))
	if err != nil {
		t.Fatalf("read initial-admin.yml: %v", err)
	}

	// Must match ludus-api/database.go initialAdminYAML field tags (`userID`, not `user_id`)
	var parsed struct {
		Name     string `yaml:"name"`
		Email    string `yaml:"email"`
		UserID   string `yaml:"userID"`
		Password string `yaml:"password"`
	}
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal initial-admin.yml: %v", err)
	}
	if parsed.UserID != "CA" || parsed.Name != "Caleb Admin" || parsed.Email != "ca@ludus.local" || parsed.Password != "SuperSecret123!" {
		t.Fatalf("unexpected initial-admin.yml payload: %+v (raw:\n%s)", parsed, string(raw))
	}
}
