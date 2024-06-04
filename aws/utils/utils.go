package utils

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/raito-io/cli/base/tag"
	"github.com/raito-io/golang-set/set"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"

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

func ConvertArnToFullname(arnString string) string {
	parts := strings.Split(arnString, ":")
	if len(parts) < 6 {
		return arnString
	}

	return strings.Join(parts[5:], ":")
}

func ConvertFullnameToArn(fullName string, service string) string {
	return fmt.Sprintf("arn:aws:%s:::%s", service, fullName)
}

func RemoveEndingWildcards(name string) string {
	return strings.TrimSuffix(name, "/*")
}

func GetTrustUserPolicyArn(resourceType, resourceId string, account string) arn.ARN {
	return arn.ARN{
		Partition: "aws",
		Service:   "iam",
		Region:    "",
		AccountID: account,
		Resource:  fmt.Sprintf("%s/%s", resourceType, resourceId),
	}
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

func GetConcurrency(cfg *config.ConfigMap) int {
	return cfg.GetIntWithDefault(constants.AwsConcurrency, 5)
}

func GetRegions(cfg *config.ConfigMap) []string {
	regions := cfg.GetString(constants.AwsRegions)

	if regions == "" {
		return []string{}
	}

	return strings.Split(regions, ",")
}

func SetSubtract[T comparable](setA set.Set[T], setB set.Set[T]) set.Set[T] {
	result := set.NewSet[T]()

	for a := range setA {
		if !setB.Contains(a) {
			result.Add(a)
		}
	}

	return result
}

func CheckNilInterface(i interface{}) bool {
	iv := reflect.ValueOf(i)
	if !iv.IsValid() {
		return true
	}

	switch iv.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Map, reflect.Func, reflect.Interface:
		return iv.IsNil()
	default:
		return false
	}
}
