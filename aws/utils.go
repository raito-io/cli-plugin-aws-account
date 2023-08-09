package aws

import (
	"fmt"
	"strings"

	"github.com/raito-io/cli/base/tag"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/hashicorp/go-hclog"
	"github.com/raito-io/cli/base"
	"github.com/raito-io/cli/base/util/config"
)

var logger hclog.Logger

func init() {
	logger = base.Logger()
}

func getTags(input []types.Tag) []*tag.Tag {
	tags := make([]*tag.Tag, 0)

	for _, t := range input {
		if t.Key != nil && t.Value != nil {
			tags = append(tags, &tag.Tag{
				Key:    *t.Key,
				Value:  *t.Value,
				Source: TagSource,
			})
		}
	}

	return tags
}

func getEmailAddressFromTags(tags []*tag.Tag, result string) string {
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
func parseAndValidateArn(inputArn string, account *string, service *string) (string, error) {
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

func convertArnToFullname(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return arn
	}

	return strings.Join(parts[5:], ":")
}

func convertFullnameToArn(fullName string, service string) string {
	// arn:aws:s3:::testing-app-server-shared-data-usage-eu-central-1-012457373382/demo/SnowflakeDataSource/*
	return fmt.Sprintf("arn:aws:%s:::%s", service, fullName)
}

func removeEndingWildcards(name string) string {
	if strings.HasSuffix(name, "/*") && len(name) > 2 {
		name = name[:len(name)-2]
	}

	return name
}

func getTrustPolicyArn(user string, configMap *config.ConfigMap) string {
	return fmt.Sprintf("arn:aws:iam::%s:user/%s", configMap.GetString(AwsAccountId), user)
}

func stripWhitespace(query string) string {
	query = strings.ReplaceAll(query, "\t", "")
	query = strings.ReplaceAll(query, "\n", "")
	query = strings.ReplaceAll(query, " ", "")

	return query
}

func getResourceNamesFromPolicyBindingArray(input []PolicyBinding) []string {
	result := []string{}
	for _, binding := range input {
		result = append(result, binding.ResourceName)
	}

	return result
}

func getConcurrency(config *config.ConfigMap) int {
	return config.GetIntWithDefault(AwsConcurrency, 5)
}
