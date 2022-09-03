package iam

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/iam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRequireProjectLevelApiKeySourceRestrictions(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "API key with no restrictions configured",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								ApiKeys: []iam.ApiKey{
									{
										Metadata:     defsecTypes.NewTestMetadata(),
										Name:         defsecTypes.String("my-key", defsecTypes.NewTestMetadata()),
										Restrictions: nil,
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "API key with android_key_restrictions block configured",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								ApiKeys: []iam.ApiKey{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Name:     defsecTypes.String("my-key", defsecTypes.NewTestMetadata()),
										Restrictions: []interface{}{
											iam.ApiKeyAndroidKeyRestrictions{
												Metadata: defsecTypes.NewTestMetadata(),
												AllowedApplications: []defsecTypes.StringValue{
													defsecTypes.String("some-app", defsecTypes.NewTestMetadata()),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "API key with browser_key_restrictions block configured",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								ApiKeys: []iam.ApiKey{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Name:     defsecTypes.String("my-key", defsecTypes.NewTestMetadata()),
										Restrictions: []interface{}{
											iam.ApiKeyBrowserKeyRestrictions{
												Metadata: defsecTypes.NewTestMetadata(),
												AllowedReferrers: []defsecTypes.StringValue{
													defsecTypes.String("example.com", defsecTypes.NewTestMetadata()),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "API key with browser_key_restrictions block configured with wildcard",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								ApiKeys: []iam.ApiKey{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Name:     defsecTypes.String("my-key", defsecTypes.NewTestMetadata()),
										Restrictions: []interface{}{
											iam.ApiKeyBrowserKeyRestrictions{
												Metadata: defsecTypes.NewTestMetadata(),
												AllowedReferrers: []defsecTypes.StringValue{
													defsecTypes.String("*.example.com", defsecTypes.NewTestMetadata()),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "API key with ios_key_restrictions block configured",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								ApiKeys: []iam.ApiKey{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Name:     defsecTypes.String("my-key", defsecTypes.NewTestMetadata()),
										Restrictions: []interface{}{
											iam.ApiKeyIosKeyRestrictions{
												Metadata: defsecTypes.NewTestMetadata(),
												AllowedBundleIds: []defsecTypes.StringValue{
													defsecTypes.String("some-id", defsecTypes.NewTestMetadata()),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "API key with server_key_restrictions block configured",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								ApiKeys: []iam.ApiKey{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Name:     defsecTypes.String("my-key", defsecTypes.NewTestMetadata()),
										Restrictions: []interface{}{
											iam.ApiKeyServerKeyRestrictions{
												Metadata: defsecTypes.NewTestMetadata(),
												AllowedIps: []defsecTypes.StringValue{
													defsecTypes.String("10.0.1.0/24", defsecTypes.NewTestMetadata()),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "API key with server_key_restrictions block configured to allow any IP",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								ApiKeys: []iam.ApiKey{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Name:     defsecTypes.String("my-key", defsecTypes.NewTestMetadata()),
										Restrictions: []interface{}{
											iam.ApiKeyServerKeyRestrictions{
												Metadata: defsecTypes.NewTestMetadata(),
												AllowedIps: []defsecTypes.StringValue{
													defsecTypes.String("0.0.0.0/0", defsecTypes.NewTestMetadata()),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.IAM = test.input
			results := CheckRequireProjectLevelApiKeySourceRestrictions.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRequireProjectLevelApiKeySourceRestrictions.Rule().LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
