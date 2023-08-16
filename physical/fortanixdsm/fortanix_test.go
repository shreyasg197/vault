package fortanix

import (
	_ "fmt"
	"os"
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/physical"
)

func TestDefaultDSMBackend(t *testing.T) {
	DoDSMBackendTest(t)
}

var reqFields = map[string]string{
	"apikey":   "FORTANIX_STORAGE_API_KEY",
	"endpoint": "FORTANIX_STORAGE_ENDPOINT",
	"prefix":   "FORTANIX_STORAGE_PREFIX",
}

func DoDSMBackendTest(t *testing.T) {
	if enabled := os.Getenv("VAULT_ACC"); enabled == "" {
		t.Skip()
	}

	backendConf := make(map[string]string, len(reqFields))
	for k, v := range reqFields {
		backendConf[k] = os.Getenv(v)
		if backendConf[k] == "" {
			t.Fatalf("Error: missing %s", k)
		}
	}

	backend, err := NewFortanixBackend(backendConf, logging.NewVaultLogger(log.Debug))
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	dsmBackend := backend.(*fortanixBackend)
	physical.ExerciseBackend(t, dsmBackend)
	physical.ExerciseBackend_ListPrefix(t, dsmBackend)
}
