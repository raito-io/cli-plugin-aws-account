package data_access

import (
	"fmt"

	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/cli/base/access_provider/sync_to_target/naming_hint"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"
)

type NameGenerator struct {
	accountId string

	accessPointNameGenerator naming_hint.UniqueGenerator
	regularNameGenerator     naming_hint.UniqueGenerator
	roleNameGenerator        naming_hint.UniqueGenerator

	accessPointPrefix string
	accessPointSuffix string
	rolePrefix        string
	roleSuffix        string
	policyPrefix      string
	policySuffix      string
	ssoRolePrefix     string
	ssoRoleSuffix     string
}

func NewNameGenerator(accountId string, params map[string]string) (*NameGenerator, error) {
	accessPointNameGenerator, err := naming_hint.NewUniqueNameGenerator(utils.Logger, "", &naming_hint.NamingConstraints{
		UpperCaseLetters:  false,
		LowerCaseLetters:  true,
		Numbers:           true,
		SpecialCharacters: "-",
		MaxLength:         30,
	})
	if err != nil {
		return nil, fmt.Errorf("new unique name generator for access point: %w", err)
	}

	regularNameGenerator, err := naming_hint.NewUniqueNameGenerator(utils.Logger, "", &naming_hint.NamingConstraints{
		UpperCaseLetters:  true,
		LowerCaseLetters:  true,
		Numbers:           true,
		SpecialCharacters: "+_",
		MaxLength:         64,
	})
	if err != nil {
		return nil, fmt.Errorf("new unique name generator non access point: %w", err)
	}

	roleNameGenerator, err := naming_hint.NewUniqueNameGenerator(utils.Logger, "", &naming_hint.NamingConstraints{
		UpperCaseLetters:  true,
		LowerCaseLetters:  true,
		Numbers:           true,
		SpecialCharacters: "+_",
		MaxLength:         19,
	})
	if err != nil {
		return nil, fmt.Errorf("new unique name generator non access point: %w", err)
	}

	return &NameGenerator{
		accountId:                accountId,
		accessPointNameGenerator: accessPointNameGenerator,
		regularNameGenerator:     regularNameGenerator,
		roleNameGenerator:        roleNameGenerator,

		rolePrefix:        params[constants.AwsAccessRolePrefix],
		roleSuffix:        params[constants.AwsAccessRoleSuffix],
		policyPrefix:      params[constants.AwsAccessPolicyPrefix],
		policySuffix:      params[constants.AwsAccessPolicySuffix],
		ssoRolePrefix:     params[constants.AwsAccessSsoRolePrefix],
		ssoRoleSuffix:     params[constants.AwsAccessSsoRoleSuffix],
		accessPointPrefix: params[constants.AwsAccessPointPrefix],
		accessPointSuffix: params[constants.AwsAccessPointSuffix],
	}, nil
}

func (ng *NameGenerator) GenerateName(ap *sync_to_target.AccessProvider, apType model.AccessProviderType) (string, error) {
	var prefix string
	var postfix string

	generator := ng.regularNameGenerator

	switch apType {
	case model.AccessPoint:
		prefix = ng.accessPointPrefix
		postfix = ng.accessPointSuffix
		generator = ng.accessPointNameGenerator
	case model.SSORole:
		if ng.ssoRolePrefix != "" {
			prefix = ng.ssoRolePrefix
		} else {
			prefix = constants.SsoRolePrefix
		}

		postfix = ng.ssoRoleSuffix + "_" + ng.accountId
		generator = ng.roleNameGenerator
	case model.Role:
		prefix = ng.rolePrefix
		postfix = ng.roleSuffix
	case model.Policy:
		prefix = ng.policyPrefix
		postfix = ng.policySuffix
	}

	name, err := generator.Generate(ap)
	if err != nil {
		return "", fmt.Errorf("generate unique name: %w", err)
	}

	return prefix + name + postfix, nil
}
