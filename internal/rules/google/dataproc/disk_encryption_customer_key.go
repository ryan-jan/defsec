package dataproc

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckDiskEncryptionCustomerKey = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0072",
		Provider:    providers.GoogleProvider,
		Service:     "dataproc",
		ShortCode:   "disk-encryption-customer-key",
		Summary:     "Cluster instance disks should be encrypted with customer-managed encryption keys",
		Impact:      "Using unmanaged keys does not allow for proper key management.",
		Resolution:  "Use customer-managed keys to encrypt Dataproc cluster instance disks.",
		Explanation: `Using unmanaged keys makes rotation and general management difficult.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformDiskEncryptionCustomerKeyGoodExamples,
			BadExamples:         terraformDiskEncryptionCustomerKeyBadExamples,
			Links:               terraformDiskEncryptionCustomerKeyLinks,
			RemediationMarkdown: terraformDiskEncryptionCustomerKeyRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Google.Dataproc.Clusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.ClusterConfig.EncryptionConfig.KMSKeyName.IsEmpty() {
				results.Add(
					"Cluster instance disks are not encrypted with a customer-managed key.",
					cluster.ClusterConfig.EncryptionConfig.KMSKeyName,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
