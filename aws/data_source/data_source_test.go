package data_source

import (
	"sort"
	"testing"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli/base/util/config"
	"github.com/stretchr/testify/assert"
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

	// Some regex includes (formerly wildcard)
	executeFilterBucketTest(t, "bucket-.*", "", buckets, []string{"bucket-1", "bucket-2"})

	// Some regex includes (formerly wildcard)
	executeFilterBucketTest(t, "bucket-.*,another-two-or-three", "", buckets, []string{"bucket-1", "bucket-2", "another-two-or-three"})

	// Some regex include and an exclude
	executeFilterBucketTest(t, "bucket-.*", "bucket-2", buckets, []string{"bucket-1"})

	// Some regex include and an exclude regex (formerly wildcard)
	executeFilterBucketTest(t, ".*other.*", ".*one.*", buckets, []string{"another-two-or-three"})

	// Regex include with a specific pattern
	executeFilterBucketTest(t, "bucket-\\d+", "", buckets, []string{"bucket-1", "bucket-2"})

	// Regex exclude with a specific pattern
	executeFilterBucketTest(t, "", "another-.*-test", buckets, []string{"bucket-1", "bucket-2", "another-two-or-three"})

	// Complex regex include and exclude
	executeFilterBucketTest(t, "^another-.*", "another-two-or-three", buckets, []string{"another-one-to-test"})
}

func executeFilterBucketTest(t *testing.T, includes string, excludes string, input []string, expected []string) {
	buckets := make([]model.AwsS3Entity, 0, len(input))
	for _, in := range input {
		buckets = append(buckets, model.AwsS3Entity{
			Key: in,
		})
	}

	filtered, err := filterBuckets(&config.ConfigMap{
		Parameters: map[string]string{
			constants.AwsS3IncludeBuckets: includes,
			constants.AwsS3ExcludeBuckets: excludes,
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

func TestIsExcluded(t *testing.T) {
	type args struct {
		name              string
		exclusionPatterns string
	}
	tests := []struct {
		name      string
		args      args
		want      bool
		expectErr bool
	}{
		{
			name: "no patterns",
			args: args{
				name:              "test-db",
				exclusionPatterns: "",
			},
			want: false,
		},
		{
			name: "simple match",
			args: args{
				name:              "test-db",
				exclusionPatterns: "test-db",
			},
			want: true,
		},
		{
			name: "wildcard match",
			args: args{
				name:              "test-db-123",
				exclusionPatterns: "test-db.*",
			},
			want: true,
		},
		{
			name: "no match",
			args: args{
				name:              "another-db",
				exclusionPatterns: "test-db.*",
			},
			want: false,
		},
		{
			name: "empty name",
			args: args{
				name:              "",
				exclusionPatterns: "test-db.*",
			},
			want: false,
		},
		{
			name: "multiple patterns match",
			args: args{
				name:              "secret-table",
				exclusionPatterns: "temp.*,.*secret.*",
			},
			want: true,
		},
		{
			name: "multiple patterns no match",
			args: args{
				name:              "prod-table",
				exclusionPatterns: "temp.*,.*secret.*",
			},
			want: false,
		},
		{
			name: "invalid regex pattern",
			args: args{
				name:              "prod-table",
				exclusionPatterns: "[a-", // Invalid regex
			},
			want:      false,
			expectErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns, err := getRegExList(tt.args.exclusionPatterns)
			if tt.expectErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			if got := isExcluded(tt.args.name, patterns); got != tt.want {
				t.Errorf("isExcluded() = %v, want %v", got, tt.want)
			}
		})
	}
}
