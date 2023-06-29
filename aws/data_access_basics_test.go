package aws

import (
	"encoding/json"
	"io/ioutil"
	"net/url"
	"testing"

	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/stretchr/testify/assert"
)

func getObjects[T any](filename string) ([]T, error) {
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var objects []T
	err = json.Unmarshal(file, &objects)
	if err != nil {
		return nil, err
	}

	return objects, nil
}

func getObject[T any](filename string) (*T, error) {
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var object T
	err = json.Unmarshal(file, &object)
	if err != nil {
		return nil, err
	}

	return &object, nil
}

func printObjects[T any](input []T, filename string) error {
	objectsJson, _ := json.MarshalIndent(input, "", "  ")
	return ioutil.WriteFile(filename, objectsJson, 0644)
}

func TestAccessSyncer_PolicyDocumentParser(t *testing.T) {

	var policy awspolicy.Policy

	policyDocumentEncoded := `%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22VisualEditor0%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22s3%3AListAllMyBuckets%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22s3%3AListBucketVersions%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22s3%3AListBucket%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D`

	policyDocument, err := url.QueryUnescape(policyDocumentEncoded)
	assert.Nil(t, err)

	err = policy.UnmarshalJSON([]byte(policyDocument))
	assert.Nil(t, err)
}

func TestSyncAccessProviderToTarget_GetApType(t *testing.T) {
	policyMap := map[string]string{"Policy1": "policy", "Policy2": "policy"}
	roleMap := map[string]string{"Role1": "role", "Role2": "role"}

	assert.Equal(t, "policy", getApType("Policy1", policyMap, roleMap))
	assert.Equal(t, "policy", getApType("Policy2", policyMap, roleMap))
	assert.Equal(t, "role", getApType("Role1", policyMap, roleMap))
	assert.Equal(t, "role", getApType("Role2", policyMap, roleMap))
	assert.Equal(t, "none", getApType("SomethingElse", policyMap, roleMap))
}
