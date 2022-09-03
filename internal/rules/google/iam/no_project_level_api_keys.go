package iam

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoProjectLevelApiKeys = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0069",
		Provider:    providers.GoogleProvider,
		Service:     "iam",
		ShortCode:   "no-project-level-api-keys",
		Summary:     "API keys should not be created for projects",
		Impact:      "Exposed API keys could lead to your account being compromised.",
		Resolution:  "Use the standard authentication flow instead of API keys.",
		Explanation: `API keys are insecure because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides. It is recommended to use standard authentication flow instead.`,
		Links: []string{
			"https://cloud.google.com/docs/authentication/api-keys",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoProjectLevelApiKeysGoodExamples,
			BadExamples:         terraformNoProjectLevelApiKeysBadExamples,
			Links:               terraformNoProjectLevelApiKeysLinks,
			RemediationMarkdown: terraformNoProjectLevelApiKeysRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, project := range s.Google.IAM.AllProjects() {
			for _, key := range project.ApiKeys {
				if key.IsUnmanaged() {
					continue
				}
				results.Add(
					"API key created at project level.",
					key,
				)
			}
		}
		return
	},
)
