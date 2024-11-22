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
	nameIndex  int
}

func TestDataAccessToTargetTestSuiteTestSuite(t *testing.T) {
	ts := DataAccessToTargetTestSuite{}

	ts.testPrefix = "TEST_" + time.Now().Format("2006-01-02T15-04")

	suite.Run(t, &ts)
}

func (s *DataAccessToTargetTestSuite) nextIndex() int {
	s.nameIndex = s.nameIndex + 1
	return s.nameIndex
}

func (s *DataAccessToTargetTestSuite) name(val string) string {
	return fmt.Sprintf("%s_%s_%d", val, s.testPrefix, s.nextIndex())
}

func (s *DataAccessToTargetTestSuite) TestAccessSyncer_CreateAllTogether() {
	accessSyncer := data_access.NewDataAccessSyncerFromConfig(s.GetConfig())

	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(s.T())

	p1Name := s.name("policy1")
	p2Name := s.name("policy2")
	r1Name := s.name("role1")
	r2Name := s.name("role2")

	aps := &sync_to_target.AccessProviderImport{
		AccessProviders: []*sync_to_target.AccessProvider{
			{
				Id:          r1Name,
				Name:        r1Name,
				Description: r1Name + " Description",
				NamingHint:  r1Name,
				Type:        ptr.String(string(model.Role)),
				ExternalId:  ptr.String("role:" + r1Name),
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
				ExternalId:  ptr.String("role:" + r2Name),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users:       []string{"m_carissa"},
					InheritFrom: []string{"ID:" + r1Name},
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
				ExternalId:  ptr.String("policy:" + p1Name),
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
				ExternalId:  ptr.String("policy:" + p2Name),
				Action:      sync_to_target.Grant,
				Who: sync_to_target.WhoItem{
					Users:       []string{"m_carissa"},
					InheritFrom: []string{"ID:" + p1Name},
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
	}

	fmt.Println("Created policy: " + p1Name)
}

//func (s *DataAccessToTargetTestSuite) TestAccessSyncer_CreateSeparate() {
//	accessSyncer := data_access.NewDataAccessSyncerFromConfig(s.GetConfig())
//
//	feedbackHandler := mocks.NewSimpleAccessProviderFeedbackHandler(s.T())
//
//	p1Name := s.name("policy1")
//	p2Name := s.name("policy2")
//	r1Name := s.name("role1")
//	r2Name := s.name("role2")
//
//	aps := &sync_to_target.AccessProviderImport{
//		AccessProviders: []*sync_to_target.AccessProvider{
//			{
//				Id:          r1Name,
//				Name:        r1Name,
//				Description: r1Name + " Description",
//				NamingHint:  r1Name,
//				Type:        ptr.String(string(model.Role)),
//				ExternalId:  ptr.String("role:" + r1Name),
//				Action:      sync_to_target.Grant,
//				Who: sync_to_target.WhoItem{
//					Users: []string{"d_hayden"},
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
//				ExternalId:  ptr.String("policy:" + p1Name),
//				Action:      sync_to_target.Grant,
//				Who: sync_to_target.WhoItem{
//					Users:       []string{"d_hayden"},
//					InheritFrom: []string{"ID:" + r1Name},
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
//	for _, feedback := range feedbackHandler.AccessProviderFeedback {
//		s.Require().Len(feedback.Errors, 0)
//	}
//
//	aps = &sync_to_target.AccessProviderImport{
//		AccessProviders: []*sync_to_target.AccessProvider{
//			{
//				Id:          r2Name,
//				Name:        r2Name,
//				Description: r2Name + " Description",
//				NamingHint:  r2Name,
//				Type:        ptr.String(string(model.Role)),
//				ExternalId:  ptr.String("role:" + r2Name),
//				Action:      sync_to_target.Grant,
//				Who: sync_to_target.WhoItem{
//					Users:       []string{"m_carissa"},
//					InheritFrom: []string{"role:" + r1Name},
//				},
//				What: []sync_to_target.WhatItem{
//					{
//						DataObject: &data_source.DataObjectReference{
//							FullName: "077954824694:eu-central-1:raito-data-corporate/operations",
//							Type:     "folder",
//						},
//						Permissions: []string{"s3:GetObject", "s3:PutObject"},
//					},
//				},
//			},
//			{
//				Id:          p2Name,
//				Name:        p2Name,
//				Description: p2Name + " Description",
//				NamingHint:  p2Name,
//				Type:        ptr.String(string(model.Policy)),
//				ExternalId:  ptr.String("policy:" + p2Name),
//				Action:      sync_to_target.Grant,
//				Who: sync_to_target.WhoItem{
//					Users:       []string{"m_carissa"},
//					InheritFrom: []string{"policy:" + p1Name},
//				},
//				What: []sync_to_target.WhatItem{
//					{
//						DataObject: &data_source.DataObjectReference{
//							FullName: "077954824694:eu-central-1:raito-data-corporate/operations",
//							Type:     "folder",
//						},
//						Permissions: []string{"s3:GetObject", "s3:PutObject"},
//					},
//				},
//			},
//		},
//	}
//
//	err = accessSyncer.SyncAccessProviderToTarget(context.Background(), aps, feedbackHandler, s.GetConfig())
//	s.Require().NoError(err)
//	s.Require().Len(feedbackHandler.AccessProviderFeedback, 2)
//	for _, feedback := range feedbackHandler.AccessProviderFeedback {
//		s.Require().Len(feedback.Errors, 0)
//	}
//}
