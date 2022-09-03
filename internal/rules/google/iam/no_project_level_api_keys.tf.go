package iam

var terraformNoProjectLevelApiKeysGoodExamples = []string{``}

var terraformNoProjectLevelApiKeysBadExamples = []string{
	`
 resource "google_apikeys_key" "primary" {
   name         = "key"
   display_name = "sample-key"
   project      = "sample-project"
 }`,
}

var terraformNoProjectLevelApiKeysLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/apikeys_key`,
}

var terraformNoProjectLevelApiKeysRemediationMarkdown = ``
