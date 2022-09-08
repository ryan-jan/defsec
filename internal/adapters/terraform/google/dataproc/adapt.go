package dataproc

import (
	"github.com/aquasecurity/defsec/pkg/providers/google/dataproc"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) dataproc.Dataproc {
	return dataproc.Dataproc{
		Clusters: adaptClusters(modules),
	}
}

func adaptClusters(modules terraform.Modules) []dataproc.Cluster {
	var clusters []dataproc.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("google_dataproc_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptCluster(resource *terraform.Block) dataproc.Cluster {
	cluster := dataproc.Cluster{
		Metadata: resource.GetMetadata(),
		Name:     resource.GetAttribute("name").AsStringValueOrDefault("", resource),
		ClusterConfig: dataproc.ClusterConfig{
			Metadata: resource.GetMetadata(),
			EncryptionConfig: dataproc.EncryptionConfig{
				Metadata:   resource.GetMetadata(),
				KMSKeyName: defsecTypes.StringDefault("", resource.GetMetadata()),
			},
		},
	}

	if cluConfig := resource.GetBlock("cluster_config"); cluConfig.IsNotNil() {
		cluster.ClusterConfig.Metadata = cluConfig.GetMetadata()
		if encConfig := cluConfig.GetBlock("encryption_config"); encConfig.IsNotNil() {
			cluster.ClusterConfig.EncryptionConfig.Metadata = encConfig.GetMetadata()
			KMSKeyNameAttr := encConfig.GetAttribute("kms_key_name")
			KMSKeyName := KMSKeyNameAttr.AsStringValueOrDefault("", encConfig)
			cluster.ClusterConfig.EncryptionConfig.KMSKeyName = KMSKeyName
		}
	}
	return cluster
}
