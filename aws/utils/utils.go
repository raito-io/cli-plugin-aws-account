package utils

import (
	"fmt"
	"strings"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/cli/base/access_provider/sync_to_target/naming_hint"
	"github.com/raito-io/cli/base/tag"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/hashicorp/go-hclog"
	"github.com/raito-io/cli/base"
	"github.com/raito-io/cli/base/util/config"
)

var Logger hclog.Logger

func init() {
	Logger = base.Logger()
}

func GetTags(input []types.Tag) []*tag.Tag {
	tags := make([]*tag.Tag, 0)

	for _, t := range input {
		if t.Key != nil && t.Value != nil {
			tags = append(tags, &tag.Tag{
				Key:    *t.Key,
				Value:  *t.Value,
				Source: constants.TagSource,
			})
		}
	}

	return tags
}

func GetEmailAddressFromTags(tags []*tag.Tag, result string) string {
	for _, t := range tags {
		if t == nil {
			continue
		}

		k := t.Key
		if strings.Contains(k, "email") {
			return t.Value
		}
	}

	return result
}

// parseAndValidateArn parses the ARN and returns the resource part. Optionally, it can verify that the account and/or service match.
func ParseAndValidateArn(inputArn string, account *string, service *string) (string, error) {
	res, err := arn.Parse(inputArn)
	if err != nil {
		return "", fmt.Errorf("error while parsing ARN: %s", err.Error())
	}

	if res.Partition != "" && res.Partition != "aws" {
		return "", fmt.Errorf("only the 'aws' partition is supported in ARNs (found %q)", res.Partition)
	}

	if account != nil && res.AccountID != "" && res.AccountID != *account {
		return "", fmt.Errorf("ARN pointing to a different account (%s)", res.AccountID)
	}

	if service != nil && res.Service != *service {
		return "", fmt.Errorf("ARN is for the wrong service (%s)", res.Service)
	}

	return res.Resource, nil
}

func ConvertArnToFullname(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return arn
	}

	return strings.Join(parts[5:], ":")
}

func ConvertFullnameToArn(fullName string, service string) string {
	return fmt.Sprintf("arn:aws:%s:::%s", service, fullName)
}

func RemoveEndingWildcards(name string) string {
	return strings.TrimSuffix(name, "/*")
}

func GetTrustPolicyArn(user string, configMap *config.ConfigMap) string {
	return fmt.Sprintf("arn:aws:iam::%s:user/%s", configMap.GetString(constants.AwsAccountId), user)
}

func StripWhitespace(query string) string {
	query = strings.ReplaceAll(query, "\t", "")
	query = strings.ReplaceAll(query, "\n", "")
	query = strings.ReplaceAll(query, " ", "")

	return query
}

func GetResourceNamesFromPolicyBindingArray(input []model.PolicyBinding) []string {
	result := []string{}
	for _, binding := range input {
		result = append(result, binding.ResourceName)
	}

	return result
}

func GetConcurrency(config *config.ConfigMap) int {
	return config.GetIntWithDefault(constants.AwsConcurrency, 5)
}

func GenerateName(ap *sync_to_target.AccessProvider) (string, error) {
	uniqueRoleNameGenerator, err := naming_hint.NewUniqueNameGenerator(Logger, "", &naming_hint.NamingConstraints{
		UpperCaseLetters:  true,
		LowerCaseLetters:  true,
		Numbers:           true,
		SpecialCharacters: "+_",
		MaxLength:         64,
	})

	if err != nil {
		return "", err
	}

	return uniqueRoleNameGenerator.Generate(ap)
}
