package iam

import (
	"reflect"

	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckRequireProjectLevelApiKeyTargetRestrictions = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0070",
		Provider:    providers.GoogleProvider,
		Service:     "iam",
		ShortCode:   "require-project-level-api-key-target-restrictions",
		Summary:     "Project level API keys should be restricted to specific target APIs",
		Impact:      "Exposed API keys could lead to your account being compromised.",
		Resolution:  "Ensure project level API keys are restricted to use only APIs that the application needs to access.",
		Explanation: `In order to reduce attack surfaces by providing least privileges, project level API keys should be restricted to use (call) only the APIs required by the specific application.`,
		Links: []string{
			"https://cloud.google.com/docs/authentication/api-keys",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformRequireProjectLevelApiKeyTargetRestrictionsGoodExamples,
			BadExamples:         terraformRequireProjectLevelApiKeyTargetRestrictionsBadExamples,
			Links:               terraformRequireProjectLevelApiKeyTargetRestrictionsLinks,
			RemediationMarkdown: terraformRequireProjectLevelApiKeyTargetRestrictionsRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, project := range s.Google.IAM.AllProjects() {
			for _, key := range project.ApiKeys {
				if key.IsUnmanaged() {
					continue
				}

				var targets []interface{}
				for _, target := range key.Restrictions {
					if reflect.TypeOf(target).String() == "iam.ApiKeyApiTargets" {
						targets = append(targets, target)
					}
				}

				if len(targets) == 0 {
					results.Add(
						"Project level API key created without API target restrictions.",
						key,
					)
				}
			}
		}
		return
	},
)
