package dataproc

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/dataproc"
	"github.com/aquasecurity/defsec/pkg/scan"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckDiskEncryptionCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    dataproc.Dataproc
		expected bool
	}{
		{
			name: "Encryption config missing KMS key link",
			input: dataproc.Dataproc{
				Clusters: []dataproc.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Name:     defsecTypes.String("simplecluster", defsecTypes.NewTestMetadata()),
						ClusterConfig: dataproc.ClusterConfig{
							Metadata: defsecTypes.NewTestMetadata(),
							EncryptionConfig: dataproc.EncryptionConfig{
								Metadata:   defsecTypes.NewTestMetadata(),
								KMSKeyName: defsecTypes.String("", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Encryption config including KMS key link",
			input: dataproc.Dataproc{
				Clusters: []dataproc.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Name:     defsecTypes.String("simplecluster", defsecTypes.NewTestMetadata()),
						ClusterConfig: dataproc.ClusterConfig{
							Metadata: defsecTypes.NewTestMetadata(),
							EncryptionConfig: dataproc.EncryptionConfig{
								Metadata:   defsecTypes.NewTestMetadata(),
								KMSKeyName: defsecTypes.String("path-to-kms-key", defsecTypes.NewTestMetadata()),
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
			testState.Google.Dataproc = test.input
			results := CheckDiskEncryptionCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckDiskEncryptionCustomerKey.Rule().LongID() {
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
