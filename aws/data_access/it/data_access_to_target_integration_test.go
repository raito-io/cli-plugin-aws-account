//go:build integration

package it

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/smithy-go/ptr"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/raito-io/cli/base/data_source"
	"github.com/raito-io/cli/base/wrappers/mocks"
	"github.com/stretchr/testify/suite"

	"github.com/raito-io/cli-plugin-aws-account/aws/data_access"
	"github.com/raito-io/cli-plugin-aws-account/aws/it"
)

type DataAccessToTargetTestSuite struct {
	it.AWSTestSuite

	testPrefix string
	testSuffix string
	nameIndex  int
}

func TestDataAccessToTargetTestSuiteTestSuite(t *testing.T) {
	ts := DataAccessToTargetTestSuite{}

	ts.testPrefix = "T_"
	ts.testSuffix = "_" + time.Now().Format("2006-01-02T15-04")

	suite.Run(t, &ts)
}

func (s *DataAccessToTargetTestSuite) nextIndex() int {
	s.nameIndex = s.nameIndex + 1
	return s.nameIndex
}

func (s *DataAccessToTargetTestSuite) name(val string) string {
	return fmt.Sprintf("%s%s%s%d", s.testPrefix, val, s.testSuffix, s.nextIndex())
}

func (s *DataAccessToTargetTestSuite) TestAccessSyncer_CreateAllTogether() {
	accessSyncer := data_access.NewDataAccessSyncerFromConfig(s.GetConfig())
	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(s.T())
	idToExternalIdMap := make(map[string]string)

	p1Name := s.name("policy-all-1")
	p2Name := s.name("policy-all-2")
	r1Name := s.name("role-all-1")
	r2Name := s.name("role-all-2")

	defer func() {
		s.deleteAps([]string{r1Name, r2Name, p1Name, p2Name}, idToExternalIdMap, []string{string(model.Role), string(model.Role), string(model.Policy), string(model.Policy)}, accessSyncer)
	}()

	aps := &sync_to_target.AccessProviderImport{
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          r1Name,
				Name:        r1Name,
				Description: r1Name + " Description",
				NamingHint:  r1Name,
				Type:        ptr.String(string(model.Role)),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users: []string{"d_hayden"},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/sales",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
			{
				Id:          r2Name,
				Name:        r2Name,
				Description: r2Name + " Description",
				NamingHint:  r2Name,
				Type:        ptr.String(string(model.Role)),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users: []string{"m_carissa"},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/operations",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
			{
				Id:          p1Name,
				Name:        p1Name,
				Description: p1Name + " Description",
				NamingHint:  p1Name,
				Type:        ptr.String(string(model.Policy)),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users:       []string{"d_hayden"},
					InheritFrom: []string{"ID:" + r1Name},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/marketing",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
			{
				Id:          p2Name,
				Name:        p2Name,
				Description: p2Name + " Description",
				NamingHint:  p2Name,
				Type:        ptr.String(string(model.Policy)),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users:       []string{"m_carissa"},
					InheritFrom: []string{"ID:" + r2Name},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/operations",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
		},
	}

	err := accessSyncer.SyncAccessProviderToTarget(context.Background(), aps, feedbackHandler, s.GetConfig())
	s.Require().NoError(err)
	s.Require().Len(feedbackHandler.AccessProviderFeedback, 4)

	for _, feedback := range feedbackHandler.AccessProviderFeedback {
		s.Require().Len(feedback.Errors, 0)
		idToExternalIdMap[feedback.AccessProvider] = *feedback.ExternalId
	}
}

func (s *DataAccessToTargetTestSuite) TestAccessSyncer_PolicyRole_CreateSeparate() {
	accessSyncer := data_access.NewDataAccessSyncerFromConfig(s.GetConfig())
	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(s.T())
	idToExternalIdMap := make(map[string]string)

	p1Name := s.name("policy-sep-1")
	p2Name := s.name("policy-sep-2")
	r1Name := s.name("role-sep-1")
	r2Name := s.name("role-sep-2")

	defer func() {
		s.deleteAps([]string{r1Name, r2Name, p1Name, p2Name}, idToExternalIdMap, []string{string(model.Role), string(model.Role), string(model.Policy), string(model.Policy)}, accessSyncer)
	}()

	aps := &sync_to_target.AccessProviderImport{
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          r1Name,
				Name:        r1Name,
				Description: r1Name + " Description",
				NamingHint:  r1Name,
				Type:        ptr.String(string(model.Role)),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users: []string{"d_hayden"},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/sales",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
			{
				Id:          r2Name,
				Name:        r2Name,
				Description: r2Name + " Description",
				NamingHint:  r2Name,
				Type:        ptr.String(string(model.Role)),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users: []string{"m_carissa"},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/operations",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
		},
	}

	err := accessSyncer.SyncAccessProviderToTarget(context.Background(), aps, feedbackHandler, s.GetConfig())
	s.Require().NoError(err)
	s.Require().Len(feedbackHandler.AccessProviderFeedback, 2)

	for _, feedback := range feedbackHandler.AccessProviderFeedback {
		s.Require().Len(feedback.Errors, 0)
		idToExternalIdMap[feedback.AccessProvider] = *feedback.ExternalId
	}

	feedbackHandler = mocks.NewSimpleAccessProviderFeedbackHandler(s.T())

	aps = &sync_to_target.AccessProviderImport{
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          p1Name,
				Name:        p1Name,
				Description: p1Name + " Description",
				NamingHint:  p1Name,
				Type:        ptr.String(string(model.Policy)),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users:       []string{"d_hayden"},
					InheritFrom: []string{idToExternalIdMap[r1Name]},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/marketing",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
			{
				Id:          p2Name,
				Name:        p2Name,
				Description: p2Name + " Description",
				NamingHint:  p2Name,
				Type:        ptr.String(string(model.Policy)),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users:       []string{"m_carissa"},
					InheritFrom: []string{idToExternalIdMap[r2Name]},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/operations",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
		},
	}

	err = accessSyncer.SyncAccessProviderToTarget(context.Background(), aps, feedbackHandler, s.GetConfig())
	s.checkNoErrors(feedbackHandler, err, 2)
}

func (s *DataAccessToTargetTestSuite) TestAccessSyncer_PolicyRole_PolicyUpdate() {
	accessSyncer := data_access.NewDataAccessSyncerFromConfig(s.GetConfig())
	idToExternalIdMap := make(map[string]string)

	p1Name := s.name("policy-update-1")
	r1Name := s.name("role-update-1")
	r2Name := s.name("role-update-2")

	defer func() {
		s.deleteAps([]string{r1Name, r2Name, p1Name}, idToExternalIdMap, []string{string(model.Role), string(model.Role), string(model.Policy)}, accessSyncer)
	}()

	aps := &sync_to_target.AccessProviderImport{
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          r1Name,
				Name:        r1Name,
				Description: r1Name + " Description",
				NamingHint:  r1Name,
				Type:        ptr.String(string(model.Role)),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users: []string{"d_hayden"},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/sales",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
			{
				Id:          r2Name,
				Name:        r2Name,
				Description: r2Name + " Description",
				NamingHint:  r2Name,
				Type:        ptr.String(string(model.Role)),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users: []string{"m_carissa"},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/operations",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
			{
				Id:          p1Name,
				Name:        p1Name,
				Description: p1Name + " Description",
				NamingHint:  p1Name,
				Type:        ptr.String(string(model.Policy)),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users:       []string{"d_hayden"},
					InheritFrom: []string{"ID:" + r1Name},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/marketing",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
		},
	}

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(s.T())
	err := accessSyncer.SyncAccessProviderToTarget(context.Background(), aps, feedbackHandler, s.GetConfig())
	s.checkNoErrors(feedbackHandler, err, 3)

	for _, feedback := range feedbackHandler.AccessProviderFeedback {
		idToExternalIdMap[feedback.AccessProvider] = *feedback.ExternalId
	}

	aps = &sync_to_target.AccessProviderImport{
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          p1Name,
				Name:        p1Name,
				Description: p1Name + " Description updated",
				NamingHint:  p1Name,
				Type:        ptr.String(string(model.Policy)),
				ExternalId:  ptr.String(idToExternalIdMap[p1Name]),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users:       []string{"m_carissa"},
					InheritFrom: []string{idToExternalIdMap[r2Name]},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/sales",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
		},
	}

	feedbackHandler = mocks.NewSimpleAccessProviderFeedbackHandler(s.T())
	err = accessSyncer.SyncAccessProviderToTarget(context.Background(), aps, feedbackHandler, s.GetConfig())
	s.checkNoErrors(feedbackHandler, err, 1)
}

func (s *DataAccessToTargetTestSuite) TestAccessSyncer_PolicyRole_PolicyRenameAndUpdate() {
	accessSyncer := data_access.NewDataAccessSyncerFromConfig(s.GetConfig())
	idToExternalIdMap := make(map[string]string)

	p1Name := s.name("policy-rename-1")
	r1Name := s.name("role-rename-1")
	r2Name := s.name("role-rename-2")

	defer func() {
		s.deleteAps([]string{r1Name, r2Name, p1Name}, idToExternalIdMap, []string{string(model.Role), string(model.Role), string(model.Policy)}, accessSyncer)
	}()

	aps := &sync_to_target.AccessProviderImport{
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          r1Name,
				Name:        r1Name,
				Description: r1Name + " Description",
				NamingHint:  r1Name,
				Type:        ptr.String(string(model.Role)),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users: []string{"d_hayden"},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/sales",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
			{
				Id:          r2Name,
				Name:        r2Name,
				Description: r2Name + " Description",
				NamingHint:  r2Name,
				Type:        ptr.String(string(model.Role)),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users: []string{"m_carissa"},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/operations",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
			{
				Id:          p1Name,
				Name:        p1Name,
				Description: p1Name + " Description",
				NamingHint:  p1Name,
				Type:        ptr.String(string(model.Policy)),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users:       []string{"d_hayden"},
					InheritFrom: []string{"ID:" + r1Name},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/marketing",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
		},
	}

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(s.T())
	err := accessSyncer.SyncAccessProviderToTarget(context.Background(), aps, feedbackHandler, s.GetConfig())
	s.checkNoErrors(feedbackHandler, err, 3)

	for _, feedback := range feedbackHandler.AccessProviderFeedback {
		idToExternalIdMap[feedback.AccessProvider] = *feedback.ExternalId
	}

	aps = &sync_to_target.AccessProviderImport{
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          p1Name,
				Name:        p1Name + " UPDATED",
				Description: p1Name + " Description updated",
				NamingHint:  p1Name + " UPDATED",
				Type:        ptr.String(string(model.Policy)),
				ExternalId:  ptr.String(idToExternalIdMap[p1Name]),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users:       []string{"m_carissa"},
					InheritFrom: []string{idToExternalIdMap[r2Name]},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/sales",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
		},
	}

	feedbackHandler = mocks.NewSimpleAccessProviderFeedbackHandler(s.T())
	err = accessSyncer.SyncAccessProviderToTarget(context.Background(), aps, feedbackHandler, s.GetConfig())
	s.checkNoErrors(feedbackHandler, err, 1)
	for _, feedback := range feedbackHandler.AccessProviderFeedback {
		idToExternalIdMap[feedback.AccessProvider] = *feedback.ExternalId
	}
}

func (s *DataAccessToTargetTestSuite) checkNoErrors(feedbackHandler *mocks.SimpleAccessProviderFeedbackHandler, err error, expectedCount int) {
	s.Require().NoError(err)
	s.Require().Len(feedbackHandler.AccessProviderFeedback, expectedCount)
	for _, feedback := range feedbackHandler.AccessProviderFeedback {
		s.Require().Len(feedback.Errors, 0)
	}
}

func (s *DataAccessToTargetTestSuite) TestAccessSyncer_AccessPointRole_AccessPointUpdate() {
	accessSyncer := data_access.NewDataAccessSyncerFromConfig(s.GetConfig())
	idToExternalIdMap := make(map[string]string)

	ap1Name := s.name("ap1")
	r1Name := s.name("role-ap-update-1")
	r2Name := s.name("role-ap-update-2")

	defer func() {
		s.deleteAps([]string{r1Name, r2Name, ap1Name}, idToExternalIdMap, []string{string(model.Role), string(model.Role), string(model.AccessPoint)}, accessSyncer)
	}()

	aps := &sync_to_target.AccessProviderImport{
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          r1Name,
				Name:        r1Name,
				Description: r1Name + " Description",
				NamingHint:  r1Name,
				Type:        ptr.String(string(model.Role)),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users: []string{"d_hayden"},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/sales",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
			{
				Id:          r2Name,
				Name:        r2Name,
				Description: r2Name + " Description",
				NamingHint:  r2Name,
				Type:        ptr.String(string(model.Role)),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users: []string{"m_carissa"},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/operations",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
			{
				Id:          ap1Name,
				Name:        ap1Name,
				Description: ap1Name + " Description",
				NamingHint:  ap1Name,
				Type:        ptr.String(string(model.AccessPoint)),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users:       []string{"d_hayden"},
					InheritFrom: []string{"ID:" + r1Name},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/marketing",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
		},
	}

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(s.T())
	err := accessSyncer.SyncAccessProviderToTarget(context.Background(), aps, feedbackHandler, s.GetConfig())
	s.checkNoErrors(feedbackHandler, err, 3)

	for _, feedback := range feedbackHandler.AccessProviderFeedback {
		idToExternalIdMap[feedback.AccessProvider] = *feedback.ExternalId
	}

	// For some reason, the access point service in AWS takes some time to see the role to link to.
	time.Sleep(10 * time.Second)

	aps = &sync_to_target.AccessProviderImport{
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          ap1Name,
				Name:        ap1Name,
				Description: ap1Name + " Description updated",
				NamingHint:  ap1Name,
				Type:        ptr.String(string(model.AccessPoint)),
				ExternalId:  ptr.String(idToExternalIdMap[ap1Name]),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users:       []string{"m_carissa"},
					InheritFrom: []string{idToExternalIdMap[r2Name]},
				},
				What: []sync_to_target.WhatItem{
					{
						DataObject: &data_source.DataObjectReference{
							FullName: "077954824694:eu-central-1:raito-data-corporate/sales",
							Type:     "folder",
						},
						Permissions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
			},
		},
	}

	feedbackHandler = mocks.NewSimpleAccessProviderFeedbackHandler(s.T())
	err = accessSyncer.SyncAccessProviderToTarget(context.Background(), aps, feedbackHandler, s.GetConfig())
	s.checkNoErrors(feedbackHandler, err, 1)
}

func (s *DataAccessToTargetTestSuite) TestAccessSyncer_ManyRoles() {
	accessSyncer := data_access.NewDataAccessSyncerFromConfig(s.GetConfig())
	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(s.T())
	idToExternalIdMap := make(map[string]string)

	roleNames := []string{}
	for i := 0; i < 30; i++ {
		roleNames = append(roleNames, fmt.Sprintf("role-many-%d", i))
	}

	roleTypes := make([]string, len(roleNames))
	for i := 0; i < len(roleNames); i++ {
		roleTypes[i] = string(model.Role)
	}

	defer func() {
		s.deleteAps(roleNames, idToExternalIdMap, roleTypes, accessSyncer)
	}()

	aps := &sync_to_target.AccessProviderImport{
		AccessProviders: []*sync_to_target.AccessProvider{},
	}

	for _, roleName := range roleNames {
		aps.AccessProviders = append(aps.AccessProviders, &sync_to_target.AccessProvider{
			Id:          roleName,
			Name:        roleName,
			Description: roleName + " Description",
			NamingHint:  roleName,
			Type:        ptr.String(string(model.Role)),
			Action:      sync_to_target.Grant,
			Who: sync_to_target.WhoItem{
				Users: []string{"d_hayden"},
			},
			What: []sync_to_target.WhatItem{
				{
					DataObject: &data_source.DataObjectReference{
						FullName: "077954824694:eu-central-1:raito-data-corporate/sales",
						Type:     "folder",
					},
					Permissions: []string{"s3:GetObject", "s3:PutObject"},
				},
			},
		})
	}

	err := accessSyncer.SyncAccessProviderToTarget(context.Background(), aps, feedbackHandler, s.GetConfig())
	s.Require().NoError(err)
	s.Require().Len(feedbackHandler.AccessProviderFeedback, len(roleNames))

	for _, feedback := range feedbackHandler.AccessProviderFeedback {
		s.Require().Len(feedback.Errors, 0)
		idToExternalIdMap[feedback.AccessProvider] = *feedback.ExternalId
	}

	// Now deleting them all
}

//
//func (s *DataAccessToTargetTestSuite) TestAccessSyncer_SSORole() {
//	config := s.GetConfig()
//
//	config.Parameters[constants.AwsOrganizationProfile] = "master"
//	config.Parameters[constants.AwsOrganizationIdentityCenterInstanceArn] = "arn:aws:sso:::instance/ssoins-680418c87609cf1b"
//	config.Parameters[constants.AwsOrganizationIdentityStore] = "d-93677226bc"
//	config.Parameters[constants.AwsOrganizationRegion] = "eu-west-1"
//
//	accessSyncer := data_access.NewDataAccessSyncerFromConfig(config)
//	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(s.T())
//	idToExternalIdMap := make(map[string]string)
//
//	sso1Name := s.name("SSORole1")
//	sso2Name := s.name("SSORole2")
//	p1Name := s.name("TestPolicy1")
//
//	defer func() {
//		s.deleteAps([]string{sso1Name, sso2Name, p1Name}, idToExternalIdMap, []string{string(model.SSORole), string(model.SSORole), string(model.Policy)}, accessSyncer)
//	}()
//
//	aps := &sync_to_target.AccessProviderImport{
//		AccessProviders: []*sync_to_target.AccessProvider{
//			{
//				Id:          sso1Name,
//				Name:        sso1Name,
//				Description: sso1Name + " Description",
//				NamingHint:  sso1Name,
//				Type:        ptr.String(string(model.SSORole)),
//				Action:      sync_to_target.Grant,
//				Who: sync_to_target.WhoItem{
//					Users: []string{"dieter@raito.io"},
//				},
//				What: []sync_to_target.WhatItem{
//					{
//						DataObject: &data_source.DataObjectReference{
//							FullName: "077954824694:eu-central-1:raito-data-corporate/sales",
//							Type:     "folder",
//						},
//						Permissions: []string{"s3:GetObject", "s3:PutObject"},
//					},
//				},
//			},
//			{
//				Id:          p1Name,
//				Name:        p1Name,
//				Description: p1Name + " Description",
//				NamingHint:  p1Name,
//				Type:        ptr.String(string(model.Policy)),
//				Action:      sync_to_target.Grant,
//				Who: sync_to_target.WhoItem{
//					Users:       []string{"d_hayden"},
//					InheritFrom: []string{"ID:" + sso1Name},
//				},
//				What: []sync_to_target.WhatItem{
//					{
//						DataObject: &data_source.DataObjectReference{
//							FullName: "077954824694:eu-central-1:raito-data-corporate/marketing",
//							Type:     "folder",
//						},
//						Permissions: []string{"s3:GetObject", "s3:PutObject"},
//					},
//				},
//			},
//		},
//	}
//
//	err := accessSyncer.SyncAccessProviderToTarget(context.Background(), aps, feedbackHandler, s.GetConfig())
//	s.Require().NoError(err)
//	s.Require().Len(feedbackHandler.AccessProviderFeedback, 2)
//
//	for _, feedback := range feedbackHandler.AccessProviderFeedback {
//		s.Require().Len(feedback.Errors, 0)
//		idToExternalIdMap[feedback.AccessProvider] = *feedback.ExternalId
//	}
//
//	aps = &sync_to_target.AccessProviderImport{
//		AccessProviders: []*sync_to_target.AccessProvider{
//			{
//				Id:          sso2Name,
//				Name:        sso2Name,
//				Description: sso2Name + " Description",
//				NamingHint:  sso2Name,
//				Type:        ptr.String(string(model.SSORole)),
//				Action:      sync_to_target.Grant,
//				Who: sync_to_target.WhoItem{
//					Users: []string{"ruben@raito.io"},
//				},
//				What: []sync_to_target.WhatItem{
//					{
//						DataObject: &data_source.DataObjectReference{
//							FullName: "077954824694:eu-central-1:raito-data-corporate/operations",
//							Type:     "folder",
//						},
//						Permissions: []string{"s3:GetObject"},
//					},
//				},
//			},
//			{
//				Id:          p1Name,
//				Name:        p1Name,
//				Description: p1Name + " Description",
//				NamingHint:  p1Name,
//				Type:        ptr.String(string(model.Policy)),
//				ExternalId:  ptr.String(idToExternalIdMap[p1Name]),
//				Action:      sync_to_target.Grant,
//				Who: sync_to_target.WhoItem{
//					Users:       []string{"m_carissa"},
//					InheritFrom: []string{"ID:" + sso2Name}, // Adding it to SSO role 2
//				},
//				DeletedWho: &sync_to_target.WhoItem{
//					Users:       []string{"d_hayden"},
//					InheritFrom: []string{idToExternalIdMap[sso1Name]}, // Removing it from SSO role 1
//				},
//				What: []sync_to_target.WhatItem{
//					{
//						DataObject: &data_source.DataObjectReference{
//							FullName: "077954824694:eu-central-1:raito-data-corporate/marketing",
//							Type:     "folder",
//						},
//						Permissions: []string{"s3:GetObject", "s3:PutObject"},
//					},
//				},
//			},
//		},
//	}
//
//	feedbackHandler = mocks.NewSimpleAccessProviderFeedbackHandler(s.T())
//
//	err = accessSyncer.SyncAccessProviderToTarget(context.Background(), aps, feedbackHandler, s.GetConfig())
//	s.Require().NoError(err)
//	s.Require().Len(feedbackHandler.AccessProviderFeedback, 2)
//
//	for _, feedback := range feedbackHandler.AccessProviderFeedback {
//		s.Require().Len(feedback.Errors, 0)
//		idToExternalIdMap[feedback.AccessProvider] = *feedback.ExternalId
//	}
//}

func (s *DataAccessToTargetTestSuite) deleteAps(ids []string, idToExternalIdMap map[string]string, types []string, accessSyncer *data_access.AccessSyncer) {
	aps := &sync_to_target.AccessProviderImport{
		AccessProviders: []*sync_to_target.AccessProvider{},
	}

	for i, id := range ids {
		aps.AccessProviders = append(aps.AccessProviders, &sync_to_target.AccessProvider{
			Id:         id,
			Name:       id,
			ExternalId: ptr.String(idToExternalIdMap[id]),
			Type:       ptr.String(types[i]),
			Action:     sync_to_target.Grant,
			Delete:     true,
		})
	}

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(s.T())

	err := accessSyncer.SyncAccessProviderToTarget(context.Background(), aps, feedbackHandler, s.GetConfig())
	s.checkNoErrors(feedbackHandler, err, len(ids))
}
