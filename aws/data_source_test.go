package aws

import (
	"github.com/raito-io/cli/base/util/config"
	"github.com/stretchr/testify/assert"
	"sort"
	"testing"
)

func TestFilterBuckets(t *testing.T) {
	buckets := []string{
		"bucket-1",
		"bucket-2",
		"another-one-to-test",
		"another-two-or-three",
	}

	// No includes or excludes
	executeFilterBucketTest(t, "", "", buckets, buckets)

	// Some simple includes
	executeFilterBucketTest(t, "bucket-1,another-one-to-test", "", buckets, []string{"bucket-1", "another-one-to-test"})

	// Some wildcard includes
	executeFilterBucketTest(t, "bucket*", "", buckets, []string{"bucket-1", "bucket-2"})

	// Some wildcard includes
	executeFilterBucketTest(t, "bucket*,another-two-or-three", "", buckets, []string{"bucket-1", "bucket-2", "another-two-or-three"})

	// Some wildcard include and an exclude
	executeFilterBucketTest(t, "bucket*", "bucket-2", buckets, []string{"bucket-1"})

	// Some wildcard include and an exclude wildcard
	executeFilterBucketTest(t, "*other*", "*one*", buckets, []string{"another-two-or-three"})
}

func executeFilterBucketTest(t *testing.T, includes string, excludes string, input []string, expected []string) {
	buckets := make([]AwsS3Entity, 0, len(input))
	for _, in := range input {
		buckets = append(buckets, AwsS3Entity{
			Key: in,
		})
	}

	filtered, err := filterBuckets(&config.ConfigMap{
		Parameters: map[string]string{
			AwsS3IncludeBuckets: includes,
			AwsS3ExcludeBuckets: excludes,
		},
	}, buckets)

	assert.NoError(t, err)

	filteredKeys := make([]string, 0, len(filtered))
	for _, f := range filtered {
		filteredKeys = append(filteredKeys, f.Key)
	}

	sort.Strings(expected)
	sort.Strings(filteredKeys)

	assert.Equal(t, expected, filteredKeys)
}
