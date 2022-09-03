package iam

var terraformRequireProjectLevelApiKeySourceRestrictionsGoodExamples = []string{
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

    android_key_restrictions {
      allowed_applications = ["some-app"]
    }
  
     browser_key_restrictions {
       allowed_referrers = ["example.com"]
     }
   }
 }`,
}

var terraformRequireProjectLevelApiKeySourceRestrictionsBadExamples = []string{
	`
 resource "google_apikeys_key" "primary" {
   name         = "key"
   display_name = "sample-key"
   project      = "sample-project"
 }`,
}

var terraformRequireProjectLevelApiKeySourceRestrictionsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/apikeys_key`,
}

var terraformRequireProjectLevelApiKeySourceRestrictionsRemediationMarkdown = ``
