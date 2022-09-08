package dataproc

var terraformDiskEncryptionCustomerKeyGoodExamples = []string{
	`
 resource "google_dataproc_cluster" "simplecluster" {
   name   = "simplecluster"
   region = "us-central1"
  
   cluster_config {
     encryption_config {
       kms_key_name = "projects/projectId/locations/region/keyRings/keyRingName/cryptoKeys/keyName"
     }
   }
 }`,
}

var terraformDiskEncryptionCustomerKeyBadExamples = []string{
	`
 resource "google_dataproc_cluster" "simplecluster" {
   name   = "simplecluster"
   region = "us-central1"
 }`,
}

var terraformDiskEncryptionCustomerKeyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/dataproc_cluster#nested_encryption_config`,
}

var terraformDiskEncryptionCustomerKeyRemediationMarkdown = ``
