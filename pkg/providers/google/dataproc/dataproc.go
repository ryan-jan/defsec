package dataproc

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Dataproc struct {
	Clusters []Cluster
}

type Cluster struct {
	defsecTypes.Metadata
	Name          defsecTypes.StringValue
	ClusterConfig ClusterConfig
}

type ClusterConfig struct {
	defsecTypes.Metadata
	EncryptionConfig EncryptionConfig
}

type EncryptionConfig struct {
	defsecTypes.Metadata
	KMSKeyName defsecTypes.StringValue
}
