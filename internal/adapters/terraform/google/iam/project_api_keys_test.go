package iam

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/google/iam"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_adaptProjectApiKeys(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  iam.ApiKey
	}{
		{
			name: "API key without restrictions",
			terraform: `
resource "google_apikeys_key" "primary" {
  name         = "key"
  display_name = "sample-key"
  project      = "sample-project"
}`,
			expected: iam.ApiKey{
				Metadata: defsecTypes.NewTestMetadata(),
				Name:     defsecTypes.String("key", defsecTypes.NewTestMetadata()),
			},
		},
		{
			name: "API key with restrictions",
			terraform: `
resource "google_apikeys_key" "primary" {
  name         = "key"
  display_name = "sample-key"
  project      = "sample-project"

  restrictions {
    android_key_restrictions {
		allowed_applications = ["some-application-id"]
	}

	api_targets {
      service = "translate.googleapis.com"
      methods = ["GET*"]
    }

    browser_key_restrictions {
      allowed_referrers = ["example.com"]
    }

	ios_key_restrictions {
		allowed_bundle_ids = ["some-bundle-id"]
	}

	server_key_restrictions {
		allowed_ips = ["10.0.1.0/24"]
	}
  }
}`,
			expected: iam.ApiKey{
				Metadata: defsecTypes.NewTestMetadata(),
				Name:     defsecTypes.String("key", defsecTypes.NewTestMetadata()),
				Restrictions: []interface{}{
					iam.ApiKeyApiTargets{
						Metadata: defsecTypes.NewTestMetadata(),
						Service:  defsecTypes.String("translate.googleapis.com", defsecTypes.NewTestMetadata()),
					},
					iam.ApiKeyAndroidKeyRestrictions{
						Metadata: defsecTypes.NewTestMetadata(),
						AllowedApplications: []defsecTypes.StringValue{
							defsecTypes.String("some-application-id", defsecTypes.NewTestMetadata()),
						},
					},
					iam.ApiKeyBrowserKeyRestrictions{
						Metadata: defsecTypes.NewTestMetadata(),
						AllowedReferrers: []defsecTypes.StringValue{
							defsecTypes.String("example.com", defsecTypes.NewTestMetadata()),
						},
					},
					iam.ApiKeyIosKeyRestrictions{
						Metadata: defsecTypes.NewTestMetadata(),
						AllowedBundleIds: []defsecTypes.StringValue{
							defsecTypes.String("some-bundle-id", defsecTypes.NewTestMetadata()),
						},
					},
					iam.ApiKeyServerKeyRestrictions{
						Metadata: defsecTypes.NewTestMetadata(),
						AllowedIps: []defsecTypes.StringValue{
							defsecTypes.String("10.0.1.0/24", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := AdaptKey(modules.GetBlocks()[0], modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
