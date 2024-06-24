package usage

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/aws/smithy-go/ptr"
	"github.com/raito-io/cli/base/data_source"
	"github.com/raito-io/cli/base/data_usage"
	"github.com/raito-io/cli/base/util/config"
	"github.com/raito-io/cli/base/wrappers/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils/trie"
)

func TestDataUsageSyncer_SyncDataUsage_NoCloudTrailBucket(t *testing.T) {
	// Given
	repoMock := NewMockdataUsageRepository(t)
	dataObjectRepoMock := NewMockdataObjectRepository(t)
	account := "accountId"
	configMap := &config.ConfigMap{
		Parameters: map[string]string{
			constants.AwsS3Enabled: "true",
		},
	}
	ctx := context.Background()

	dataUsageWrapper := mocks.NewDataUsageStatementHandler(t)

	syncer := DataUsageSyncer{account: account, repo: repoMock, dataObjectRepo: dataObjectRepoMock, configMap: configMap}

	// Expect
	dataObjectRepoMock.EXPECT().GetAvailableObjectTypes(ctx, configMap).Return(
		trie.FromMap("/", map[string]string{"bucket1/folder1/folder2/file1": "file", "bucket1/folder1/folder2/file2": "file", "bucket1/folder1/folder2": "folder", "bucket1/folder1": "folder"}),
		nil)

	// When
	err := syncer.syncDataUsage(ctx, dataUsageWrapper, configMap)

	// Then
	require.NoError(t, err)
}

func TestDataUsageSyncer_SyncDataUsage(t *testing.T) {
	// Given
	repoMock := NewMockdataUsageRepository(t)
	dataObjectRepoMock := NewMockdataObjectRepository(t)
	account := "accountId"
	configMap := &config.ConfigMap{
		Parameters: map[string]string{
			constants.AwsS3Enabled:          "true",
			constants.AwsS3CloudTrailBucket: "cloudtrail-bucket",
		},
	}
	ctx := context.Background()

	dataUsageWrapper := mocks.NewSimpleDataUsageStatementHandler(t)

	tnow := time.Now()
	filePrefix := fmt.Sprintf("cloudtrail-bucket/AWSLogs/%s/CloudTrail/eu-central-1/%04d/%02d/%02d/", account, tnow.Year(), tnow.Month(), tnow.Day())

	syncer := DataUsageSyncer{account: account, repo: repoMock, dataObjectRepo: dataObjectRepoMock, configMap: configMap}

	fileContent, err := marshallAndCompressData(t, model.CloudTrailLog{
		Records: []model.CloudtrailRecord{
			{
				UserIdentity: &model.UserIdentity{
					Type:          ptr.String("AssumedRole"),
					Arn:           ptr.String("arn:aws:sts::accountId:assumed-role/AWSReservedSSO_AWSAdministratorAccess_randomPostFix/user@raito.io"),
					PrincipalId:   ptr.String("SFSAWERASFASR:user@raito.io"),
					AccountId:     ptr.String("accountId"),
					SessionIssuer: nil,
				},
				EventTime:       &tnow,
				EventSource:     ptr.String("s3.amazonaws.com"),
				EventName:       ptr.String("GetObject"),
				AwsRegion:       ptr.String("eu-central-1"),
				SourceIPAddress: ptr.String("2.2.2.2"),
				EventID:         ptr.String("eventId1"),
				ReadOnly:        true,
				Resources: []model.AwsResource{
					{
						Type: ptr.String("AWS::S3::Object"),
						Arn:  ptr.String("arn:aws:s3:::bucket1/folder1/folder2/file1"),
					},
				},
			},
			{
				UserIdentity: &model.UserIdentity{
					Type:          ptr.String("AssumedRole"),
					Arn:           ptr.String("arn:aws:sts::accountId:assumed-role/AWSReservedSSO_AWSAdministratorAccess_randomPostFix/user@raito.io"),
					PrincipalId:   ptr.String("SFSAWERASFASR:user@raito.io"),
					AccountId:     ptr.String("accountId"),
					SessionIssuer: nil,
				},
				EventTime:       &tnow,
				EventSource:     ptr.String("s3.amazonaws.com"),
				EventName:       ptr.String("PutObject"),
				AwsRegion:       ptr.String("eu-central-1"),
				SourceIPAddress: ptr.String("2.2.2.2"),
				EventID:         ptr.String("eventId2"),
				ReadOnly:        true,
				Resources: []model.AwsResource{
					{
						Type: ptr.String("AWS::S3::Object"),
						Arn:  ptr.String("arn:aws:s3:::bucket1/folder1/folder2/file2"),
					},
				},
				Bytes: &model.EventBytes{
					BytesIn:  100,
					BytesOut: 350,
				},
			},
		},
	})
	require.NoError(t, err)

	// Expect
	dataObjectRepoMock.EXPECT().GetAvailableObjectTypes(ctx, configMap).Return(
		trie.FromMap("/", map[string]string{"accountId:eu-central-1:bucket1/folder1/folder2/file1": "file", "accountId:eu-central-1:bucket1/folder1/folder2/file2": "file", "accountId:eu-central-1:bucket1/folder1/folder2": "folder", "accountId:eu-central-1:bucket1/folder1": "folder"}),
		nil)
	repoMock.EXPECT().ListFiles(ctx, "cloudtrail-bucket", (*string)(nil)).Return([]model.AwsS3Entity{{Type: data_source.File, Region: "eu-central-1", Key: filePrefix + "usageFile1.json.gz", ParentKey: filePrefix}}, "eu-central-1", nil)
	repoMock.EXPECT().GetFile(ctx, "cloudtrail-bucket", filePrefix+"usageFile1.json.gz", ptr.String("eu-central-1")).Return(fileContent, nil)

	// When
	err = syncer.syncDataUsage(ctx, dataUsageWrapper, configMap)

	// Then
	require.NoError(t, err)

	assert.ElementsMatch(t, dataUsageWrapper.Statements, []data_usage.Statement{
		{
			ExternalId: "eventId1",
			AccessedDataObjects: []data_usage.UsageDataObjectItem{
				{
					DataObject: data_usage.UsageDataObjectReference{
						FullName: "accountId:eu-central-1:bucket1/folder1/folder2/file1",
						Type:     "file",
					},
					Permissions:      []string{"s3:GetObject"},
					GlobalPermission: data_usage.Read,
				},
			},
			User:      "user@raito.io",
			Role:      "",
			Success:   true,
			Status:    "",
			Query:     "",
			StartTime: tnow.Unix(),
			EndTime:   0,
			Bytes:     0,
			Rows:      0,
			Credits:   0,
		},
		{
			ExternalId: "eventId2",
			AccessedDataObjects: []data_usage.UsageDataObjectItem{
				{
					DataObject: data_usage.UsageDataObjectReference{
						FullName: "accountId:eu-central-1:bucket1/folder1/folder2/file2",
						Type:     "file",
					},
					Permissions:      []string{"s3:PutObject"},
					GlobalPermission: data_usage.Write,
				},
			},
			User:      "user@raito.io",
			Role:      "",
			Success:   true,
			Status:    "",
			Query:     "",
			StartTime: tnow.Unix(),
			EndTime:   0,
			Bytes:     450,
			Rows:      0,
			Credits:   0,
		},
	})
}

func marshallAndCompressData(t *testing.T, d interface{}) (io.ReadCloser, error) {
	t.Helper()

	jsonData, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	buffer := new(bytes.Buffer)
	gzipWriter := gzip.NewWriter(buffer)

	defer gzipWriter.Close()

	_, err = gzipWriter.Write(jsonData)
	if err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	return io.NopCloser(buffer), nil

}
