package registry

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestEmbeddedGPT62CodexCatalogs(t *testing.T) {
	var catalog staticModelsJSON
	if err := json.Unmarshal(embeddedModelsJSON, &catalog); err != nil {
		t.Fatal(err)
	}
	if err := validateModelsCatalog(&catalog); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCodexClientModelsJSON(embeddedCodexClientModelsJSON); err != nil {
		t.Fatal(err)
	}
	var clientCatalog codexClientModelsPayload
	if err := json.Unmarshal(embeddedCodexClientModelsJSON, &clientCatalog); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"gpt-6.2-sol", "gpt-6.2-astra"} {
		var template map[string]any
		for _, candidate := range clientCatalog.Models {
			if candidate["slug"] == id {
				template = candidate
				break
			}
		}
		if template == nil {
			t.Fatalf("missing native Codex template for %s", id)
		}
		plans := template["available_in_plans"].([]any)
		if slices.Contains(plans, any("free")) {
			t.Fatalf("%s must not advertise an unverified Free entitlement", id)
		}
		for tier, models := range map[string][]*ModelInfo{
			"team": catalog.CodexTeam, "plus": catalog.CodexPlus, "pro": catalog.CodexPro,
		} {
			var info *ModelInfo
			for _, candidate := range models {
				if candidate.ID == id {
					info = candidate
					break
				}
			}
			if info == nil {
				t.Fatalf("%s is absent from the %s catalog", id, tier)
			}
			if info.ContextLength != int(template["context_window"].(float64)) ||
				info.MaxCompletionTokens != 128000 || !info.SupportConfigurationUpdate {
				t.Fatalf("%s/%s metadata disagrees with native Codex capabilities: %+v", tier, id, info)
			}
			if info.Thinking == nil || !slices.Contains(info.Thinking.Levels, "max") {
				t.Fatalf("%s/%s is missing max reasoning", tier, id)
			}
		}
		for _, info := range catalog.CodexFree {
			if info.ID == id {
				t.Fatalf("%s must not be listed for Free accounts", id)
			}
		}
	}
}
