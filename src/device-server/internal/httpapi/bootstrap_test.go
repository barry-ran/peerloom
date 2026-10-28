package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBootstrapAdvertisesManagedTURNWithoutRequiringDeployedNodes(t *testing.T) {
	api := New(nil)
	response := httptest.NewRecorder()
	api.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/bootstrap", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status %d", response.Code)
	}
	var value Bootstrap
	if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if value.APIVersion != 1 || value.SignalingPath != "/v1/device-signal" || !value.WebRTCDTLSRequired || !value.ManagedTURN || value.ApplicationE2EE {
		t.Fatal("incorrect capabilities")
	}
	if len(value.RegistrationModes) != 1 || value.RegistrationModes[0] != "grant" || len(value.ChannelTypes) != 2 {
		t.Fatal("unimplemented mode advertised")
	}
	response = httptest.NewRecorder()
	api.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/bootstrap", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatal("bootstrap accepted mutation")
	}
}
