package aws

import (
	"fmt"
	"github.com/raito-io/cli/base/tag"
	"strings"

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
				Source: "AWS",
			})
		}
	}

	return tags
}

func getEmailAddressFromTags(tags []*tag.Tag, result string) string {
	for _, t := range tags {
		if strings.Contains(t.Key, "email") {
			return t.Value
		}
	}

	return result
}

func findTagValue(tags []*tag.Tag, key string) *string {
	for _, t := range tags {
		if t.Key == key {
			return &t.Value
		}
	}

	return nil
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

func getTrustPolicyArn(user string, configMap *config.ConfigMap) string {
	return fmt.Sprintf("arn:aws:iam::%s:user/%s", configMap.GetString(AwsAccountId), user)
}

func prefixActionsWithService(service string, actions ...string) []string {
	result := []string{}
	for _, action := range actions {
		result = append(result, fmt.Sprintf("%s:%s", service, action))
	}

	return result
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
