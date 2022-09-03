package iam

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/iam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRequireProjectLevelApiKeyTargetRestrictions(t *testing.T) {
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
			name: "API key with api_targets restriction configured",
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
											iam.ApiKeyApiTargets{
												Metadata: defsecTypes.NewTestMetadata(),
												Service:  defsecTypes.String("storage.googleapis.com", defsecTypes.NewTestMetadata()),
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
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.IAM = test.input
			results := CheckRequireProjectLevelApiKeyTargetRestrictions.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRequireProjectLevelApiKeyTargetRestrictions.Rule().LongID() {
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
