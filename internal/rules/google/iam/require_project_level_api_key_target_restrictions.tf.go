package iam

var terraformRequireProjectLevelApiKeyTargetRestrictionsGoodExamples = []string{
	`
 resource "google_apikeys_key" "primary" {
   name         = "key"
   display_name = "sample-key"
   project      = "sample-project"
  
   restrictions {
     api_targets {
       service = "translate.googleapis.com"
       methods = ["GET*"]
     }
  
     browser_key_restrictions {
       allowed_referrers = ["example.com"]
     }
   }
 }`,
}

var terraformRequireProjectLevelApiKeyTargetRestrictionsBadExamples = []string{
	`
 resource "google_apikeys_key" "primary" {
   name         = "key"
   display_name = "sample-key"
   project      = "sample-project"
 }`,
}

var terraformRequireProjectLevelApiKeyTargetRestrictionsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/apikeys_key`,
}

var terraformRequireProjectLevelApiKeyTargetRestrictionsRemediationMarkdown = ``
