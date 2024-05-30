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
}

func NewNameGenerator(accountId string) (*NameGenerator, error) {
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

	return &NameGenerator{
		accountId:                accountId,
		accessPointNameGenerator: accessPointNameGenerator,
		regularNameGenerator:     regularNameGenerator,
	}, nil
}

func (ng *NameGenerator) GenerateName(ap *sync_to_target.AccessProvider, apType model.AccessProviderType) (string, error) {
	var prefix string
	var postfix string

	generator := ng.regularNameGenerator

	switch apType { //nolint:exhaustive // Default is already set
	case model.AccessPoint:
		generator = ng.accessPointNameGenerator
	case model.SSORole:
		prefix = constants.SsoRolePrefix
		postfix = "_" + ng.accountId
	}

	name, err := generator.Generate(ap)
	if err != nil {
		return "", fmt.Errorf("generate unique name: %w", err)
	}

	return prefix + name + postfix, nil
}
