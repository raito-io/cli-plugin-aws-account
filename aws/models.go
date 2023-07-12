package aws

import (
	"time"

	"github.com/raito-io/cli/base/tag"

	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli/base/access_provider/sync_from_target"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
)

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

type PolicyType string

const (
	Role              PolicyType = "aws_role"
	SSORole           PolicyType = "aws_sso_role"
	ManagedPolicy     PolicyType = "aws_managed_policy"
	InlinePolicyUser  PolicyType = "aws_inline_policy_user"
	InlinePolicyRole  PolicyType = "aws_inline_policy_role"
	InlinePolicyGroup PolicyType = "aws_inline_policy_group"
)

type AccessProviderInputExtended struct {
	ApInput      *sync_from_target.AccessProvider
	LastUsedDate *time.Time
	PolicyType   PolicyType
	InlineParent *string
}

type RoleEntity struct {
	ARN                      string
	Name                     string
	Id                       string
	Description              string
	AssumeRolePolicyDocument *string
	Tags                     []*tag.Tag
	LastUsedDate             *time.Time
}

type PolicyEntity struct {
	ARN                      string
	Name                     string
	Id                       string
	Description              string
	AttachmentCount          int32
	PolicyType               PolicyType
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

type AwsS3Entity struct {
	Type      string
	Key       string
	ParentKey string
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

type EventBytes struct {
	BytesIn  float32 `json:"bytesTransferredIn"`
	BytesOut float32 `json:"bytesTransferredOut"`
}

type AwsRecource struct {
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
	Resources          []AwsRecource `json:"resources"`
	EventType          *string       `json:"eventType"`
	ManagementEvent    bool          `json:"managementEvent"`
	RecipientAccountId *string       `json:"recipientAccountId"`
	SharedEventID      *string       `json:"sharedEventID"`
	EventCategory      *string       `json:"eventCategory"`
}

type CloudTrailLog struct {
	Records []CloudtrailRecord `json:"Records"`
}
