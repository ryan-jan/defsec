package iam

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/terraform"

	"github.com/aquasecurity/defsec/pkg/providers/google/iam"
)

// see https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/apikeys_key

func (a *adapter) adaptKey(keyBlock *terraform.Block) iam.ApiKey {
	return AdaptKey(keyBlock, a.modules)
}

func AdaptKey(keyBlock *terraform.Block, modules terraform.Modules) iam.ApiKey {
	key := iam.ApiKey{
		Metadata: keyBlock.GetMetadata(),
		Name:     keyBlock.GetAttribute("name").AsStringValueOrDefault("", keyBlock),
	}

	restrictionsBlock := keyBlock.GetBlock("restrictions")
	for _, resBlock := range restrictionsBlock.GetBlocks("api_targets") {
		res := iam.ApiKeyApiTargets{
			Metadata: resBlock.GetMetadata(),
			Service:  resBlock.GetAttribute("service").AsStringValueOrDefault("", resBlock),
		}
		key.Restrictions = append(key.Restrictions, res)
	}

	for _, resBlock := range restrictionsBlock.GetBlocks("android_key_restrictions") {
		res := iam.ApiKeyAndroidKeyRestrictions{
			Metadata:            resBlock.GetMetadata(),
			AllowedApplications: resBlock.GetAttribute("allowed_applications").AsStringValueSliceOrEmpty(resBlock),
		}
		key.Restrictions = append(key.Restrictions, res)
	}

	for _, resBlock := range restrictionsBlock.GetBlocks("browser_key_restrictions") {
		res := iam.ApiKeyBrowserKeyRestrictions{
			Metadata:         resBlock.GetMetadata(),
			AllowedReferrers: resBlock.GetAttribute("allowed_referrers").AsStringValueSliceOrEmpty(resBlock),
		}
		key.Restrictions = append(key.Restrictions, res)
	}

	for _, resBlock := range restrictionsBlock.GetBlocks("ios_key_restrictions") {
		res := iam.ApiKeyIosKeyRestrictions{
			Metadata:         resBlock.GetMetadata(),
			AllowedBundleIds: resBlock.GetAttribute("allowed_bundle_ids").AsStringValueSliceOrEmpty(resBlock),
		}
		key.Restrictions = append(key.Restrictions, res)
	}

	for _, resBlock := range restrictionsBlock.GetBlocks("server_key_restrictions") {
		res := iam.ApiKeyServerKeyRestrictions{
			Metadata:   resBlock.GetMetadata(),
			AllowedIps: resBlock.GetAttribute("allowed_ips").AsStringValueSliceOrEmpty(resBlock),
		}
		key.Restrictions = append(key.Restrictions, res)
	}

	return key
}

func (a *adapter) adaptProjectApiKeys() {
	for _, keyBlock := range a.modules.GetResourcesByType("google_apikeys_key") {
		key := a.adaptKey(keyBlock)
		projectAttr := keyBlock.GetAttribute("project")
		if projectAttr.IsString() {
			var foundProject bool
			projectID := projectAttr.Value().AsString()
			for i, project := range a.projects {
				if project.id == projectID {
					project.project.ApiKeys = append(project.project.ApiKeys, key)
					a.projects[i] = project
					foundProject = true
					break
				}
			}
			if foundProject {
				continue
			}
		}

		if refBlock, err := a.modules.GetReferencedBlock(projectAttr, keyBlock); err == nil {
			if refBlock.TypeLabel() == "google_project" {
				var foundProject bool
				for i, project := range a.projects {
					if project.blockID == refBlock.ID() {
						project.project.ApiKeys = append(project.project.ApiKeys, key)
						a.projects[i] = project
						foundProject = true
						break
					}
				}
				if foundProject {
					continue
				}

			}
		}

		// we didn't find the project - add an unmanaged one
		a.projects = append(a.projects, parentedProject{
			project: iam.Project{
				Metadata:          defsecTypes.NewUnmanagedMetadata(),
				AutoCreateNetwork: defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
				ApiKeys:           []iam.ApiKey{key},
				Members:           nil,
				Bindings:          nil,
			},
		})
	}
}
