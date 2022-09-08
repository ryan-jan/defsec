package dataproc

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/pkg/providers/google/dataproc"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  dataproc.Dataproc
	}{
		{
			name: "basic",
			terraform: `
resource "google_dataproc_cluster" "simplecluster" {
  name   = "simplecluster"
	
  cluster_config {
    encryption_config {
      kms_key_name = "path-to-kms-key"
	}
  }
}`,
			expected: dataproc.Dataproc{
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
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
resource "google_dataproc_cluster" "simplecluster" {
  name   = "simplecluster"
	
  cluster_config {
    encryption_config {
	  kms_key_name = "path-to-kms-key"
	}
  }
}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	cluster := adapted.Clusters[0]

	assert.Equal(t, 5, cluster.ClusterConfig.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, cluster.ClusterConfig.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, cluster.ClusterConfig.EncryptionConfig.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 8, cluster.ClusterConfig.EncryptionConfig.GetMetadata().Range().GetEndLine())
}
