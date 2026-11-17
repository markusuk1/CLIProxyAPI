package models

import (
	"slices"
	"testing"
)

func TestGPT62ModelsUseNativeClientTemplates(t *testing.T) {
	response := BuildResponseForClient([]map[string]any{
		{"id": "gpt-6.2-sol"}, {"id": "gpt-6.2-astra"},
	}, nil, true, "0.167.0")
	models := response["models"].([]map[string]any)
	if len(models) != 2 {
		t.Fatalf("model count = %d, want 2", len(models))
	}
	for _, model := range models {
		id := stringModelValue(model, "slug")
		wantContext := 272000
		if id == "gpt-6.2-sol" {
			wantContext = 500000
			if !slices.Contains(model["input_modalities"].([]any), any("audio")) {
				t.Fatal("GPT-6.2 Sol lost its upstream audio modality")
			}
		}
		if got := intModelValue(model, "context_window"); got != wantContext {
			t.Fatalf("%s context_window = %d, want %d", id, got, wantContext)
		}
		if got := stringModelValue(model, "minimal_client_version"); got != "0.166.0" {
			t.Fatalf("%s minimal_client_version = %q, want native template version", id, got)
		}
		if got := stringModelValue(model, "default_reasoning_level"); got != "low" {
			t.Fatalf("%s default_reasoning_level = %q, want low", id, got)
		}
		if got := stringModelValue(model, "base_instructions"); got == "" || got == codexClientFallbackInstructions {
			t.Fatalf("%s did not receive its native instructions", id)
		}
	}
}
