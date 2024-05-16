package model

import (
	"time"

	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/access_provider/sync_from_target"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	ds "github.com/raito-io/cli/base/data_source"
	"github.com/raito-io/cli/base/tag"
)

var GlueTable = "glue-" + ds.Table

type AccessProviderType string

const (
	Role        AccessProviderType = "aws_role"
	SSORole     AccessProviderType = "aws_sso_role"
	Policy      AccessProviderType = "aws_policy"
	AccessPoint AccessProviderType = "aws_access_point"
)

type AccessProviderInputExtended struct {
	ApInput      *sync_from_target.AccessProvider
	LastUsedDate *time.Time
	PolicyType   AccessProviderType
}

type RoleEntity struct {
	ARN                      string
	Name                     string
	Id                       string
	Description              string
	AssumeRolePolicyDocument *string
	AssumeRolePolicy         *awspolicy.Policy
	Tags                     []*tag.Tag
	LastUsedDate             *time.Time
}

type PolicyEntity struct {
	ARN                      string
	Name                     string
	Id                       string
	Description              string
	AttachmentCount          int32
	PolicyType               AccessProviderType
	InlineParent             *string
	AssumeRolePolicyDocument *string
	AwsManaged               bool
	PolicyDocument           *string
	PolicyParsed             *awspolicy.Policy
	Tags                     []*tag.Tag
	GroupBindings            []PolicyBinding
	UserBindings             []PolicyBinding
	RoleBindings             []PolicyBinding
}

type PolicyBinding struct {
	Type         string // user, group, role
	ResourceId   string
	ResourceName string
	PolicyName   string
}

type UserIdentity struct {
	Type          *string     `json:"type"`
	InvokedBy     *string     `json:"invokedBy"`
	Arn           *string     `json:"arn"`
	PrincipalId   *string     `json:"principalId"`
	AccountId     *string     `json:"accountId"`
	UserName      *string     `json:"userName"`
	SessionIssuer interface{} `json:"sessionIssuer"`
}

type GroupEntity struct {
	ARN        string
	ExternalId string
	Name       string
	Members    []string
}

type UserEntity struct {
	ARN        string
	ExternalId string
	Name       string
	Email      string //not natively used in AWS
	Tags       []*tag.Tag
}

type ActionMetadata struct {
	Action        string
	Description   string
	AccessLevel   string
	ResourceTypes string
}

type AccessWithWho struct {
	Name string
	What []sync_to_target.WhatItem
	Who  sync_to_target.WhoItem
}

type EventBytes struct {
	BytesIn  float32 `json:"bytesTransferredIn"`
	BytesOut float32 `json:"bytesTransferredOut"`
}

type AwsResource struct {
	AccountId *string `json:"accountId"`
	Type      *string `json:"type"`
	Arn       *string `json:"ARN"`
}

type CloudtrailRecord struct {
	UserIdentity *UserIdentity `json:"userIdentity"`
	// Test               interface{}   `json:"userIdentity"`
	EventTime          *time.Time    `json:"eventTime"`
	EventSource        *string       `json:"eventSource"`
	EventName          *string       `json:"eventName"`
	AwsRegion          *string       `json:"awsRegion"`
	SourceIPAddress    *string       `json:"sourceIPAddress"`
	UserAgent          *string       `json:"userAgent"`
	Bytes              *EventBytes   `json:"additionalEventData"`
	EventID            *string       `json:"eventID"`
	ReadOnly           bool          `json:"readOnly"`
	Resources          []AwsResource `json:"resources"`
	EventType          *string       `json:"eventType"`
	ManagementEvent    bool          `json:"managementEvent"`
	RecipientAccountId *string       `json:"recipientAccountId"`
	SharedEventID      *string       `json:"sharedEventID"`
	EventCategory      *string       `json:"eventCategory"`
}

type CloudTrailLog struct {
	Records []CloudtrailRecord `json:"Records"`
}

type AwsS3Entity struct {
	Type      string
	Region    string
	Key       string
	ParentKey string
}

type AwsS3AccessPoint struct {
	Name           string
	Arn            string
	Bucket         string
	PolicyDocument *string
	PolicyParsed   *awspolicy.Policy
}
