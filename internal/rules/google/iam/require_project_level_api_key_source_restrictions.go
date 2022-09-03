package iam

import (
	"reflect"
	"regexp"

	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/providers/google/iam"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckRequireProjectLevelApiKeySourceRestrictions = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0071",
		Provider:    providers.GoogleProvider,
		Service:     "iam",
		ShortCode:   "require-project-level-api-key-source-restrictions",
		Summary:     "Project level API keys should be restricted to allow only specific source hosts",
		Impact:      "Exposed API keys could lead to your account being compromised.",
		Resolution:  "Ensure project level API keys are restricted to use by only specific hosts and apps.",
		Explanation: `In order to reduce attack vectors, API keys should be restricted only to trusted hosts, HTTP referrers and applications.`,
		Links: []string{
			"https://cloud.google.com/docs/authentication/api-keys",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformRequireProjectLevelApiKeySourceRestrictionsGoodExamples,
			BadExamples:         terraformRequireProjectLevelApiKeySourceRestrictionsBadExamples,
			Links:               terraformRequireProjectLevelApiKeySourceRestrictionsLinks,
			RemediationMarkdown: terraformRequireProjectLevelApiKeySourceRestrictionsRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, project := range s.Google.IAM.AllProjects() {
			for _, key := range project.ApiKeys {
				if key.IsUnmanaged() {
					continue
				}

				var sources []interface{}
				for _, source := range key.Restrictions {
					if reflect.TypeOf(source).String() == "iam.ApiKeyAndroidKeyRestrictions" {
						sources = append(sources, source)
					}
					if reflect.TypeOf(source).String() == "iam.ApiKeyBrowserKeyRestrictions" {
						src := source.(iam.ApiKeyBrowserKeyRestrictions)
						matches := false
						for _, allow := range src.AllowedReferrers {
							match, _ := regexp.MatchString(`^\*$|^(\*\.)\w+(\.\w+)*(\/\*)?$`, allow.Value())
							if match {
								matches = true
							}
						}
						if matches {
							results.Add(
								"Project level API key creation with browser key restrictions should not use wildcards.",
								src,
							)
						}
						sources = append(sources, source)
					}
					if reflect.TypeOf(source).String() == "iam.ApiKeyIosKeyRestrictions" {
						sources = append(sources, source)
					}
					if reflect.TypeOf(source).String() == "iam.ApiKeyServerKeyRestrictions" {
						src := source.(iam.ApiKeyServerKeyRestrictions)
						matches := false
						for _, allow := range src.AllowedIps {
							match, _ := regexp.MatchString(`^::0$|0\.0\.0\.0(\/0)?$`, allow.Value())
							if match {
								matches = true
							}
						}
						if matches {
							results.Add(
								"Project level API key creation with server key restrictions should not allow all hosts.",
								src,
							)
						}
						sources = append(sources, source)
					}
				}

				if len(sources) == 0 {
					results.Add(
						"Project level API key created without source host/app restrictions.",
						key,
					)
				}
			}
		}
		return
	},
)
