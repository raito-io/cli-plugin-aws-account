//go:build integration

package it

import (
	"context"
	"testing"

	"github.com/raito-io/cli-plugin-aws-account/aws"
	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli/base/access_provider/sync_from_target"
	"github.com/raito-io/cli/base/wrappers/mocks"
	"github.com/stretchr/testify/suite"
)

type DataAccessFromTargetTestSuite struct {
	AWSTestSuite
}

func TestDataAccessFromTargetTestSuiteTestSuite(t *testing.T) {
	ts := DataAccessFromTargetTestSuite{}

	suite.Run(t, &ts)
}

func (s *DataAccessFromTargetTestSuite) TestAccessSyncer_FetchS3AccessPointAccessProviders() {
	accessSyncer := aws.NewDataAccessSyncerFromConfig(s.GetConfig())

	aps, err := accessSyncer.FetchS3AccessPointAccessProviders(context.Background(), s.GetConfig(), nil)
	s.NoError(err)
	s.Len(aps, 1)
	s.Equal("operations", aps[0].ApInput.Name)
	s.Equal("operations", aps[0].ApInput.ActualName)
	s.Equal(string(model.AccessPoint), *aps[0].ApInput.Type)
	s.Equal(sync_from_target.Grant, aps[0].ApInput.Action)
	s.Len(aps[0].ApInput.Who.Users, 1)
	s.Equal(aps[0].ApInput.Who.Users[0], "m_carissa")
	s.Len(aps[0].ApInput.Who.AccessProviders, 1)
	s.Equal(constants.RoleTypePrefix+"MarketingRole", aps[0].ApInput.Who.AccessProviders[0])
	s.Equal("raito-data-corporate/operations", aps[0].ApInput.What[0].DataObject.FullName)
	s.Equal("s3:GetObject", aps[0].ApInput.What[0].Permissions[0])
	s.True(aps[0].ApInput.Incomplete == nil || !*aps[0].ApInput.Incomplete)
}

func (s *DataAccessFromTargetTestSuite) TestAccessSyncer_FetchTest() {
	accessSyncer := aws.NewDataAccessSyncerFromConfig(s.GetConfig())

	handler := mocks.NewSimpleAccessProviderHandler(s.T(), 100)
	config := s.GetConfig()
	// Skipping AWS managed policies for performance reasons
	config.Parameters[constants.AwsAccessManagedPolicyExcludes] = "Amazon.+,AWS.+"
	err := accessSyncer.SyncAccessProvidersFromTarget(context.Background(), handler, config)

	expectedAps := map[string]expectedAP{
		"accesspoint:operations":             {whoUsers: []string{"m_carissa"}, whoAps: []string{"role:MarketingRole"}, name: "operations", whatDos: []string{"raito-data-corporate/operations"}, whatPermissions: []string{"s3:GetObject"}, incomplete: false, apType: "aws_access_point"},
		"role:MarketingRole":                 {whoUsers: []string{"m_carissa"}, name: "MarketingRole", incomplete: false, apType: "aws_role"},
		"user:d_hayden|inline:DustinPolicy|": {whoUsers: []string{"d_hayden"}, name: "User d_hayden inline policies", whatDos: []string{"raito-data-corporate/operations"}, whatPermissions: []string{"s3:GetObject"}, incomplete: false, apType: "aws_policy"},
		"group:Sales|inline:SalesPolicy|":    {whoGroups: []string{"Sales"}, name: "Group Sales inline policies", whatDos: []string{"raito-data-corporate/sales"}, whatPermissions: []string{"s3:GetObject", "s3:PutObject"}, incomplete: false, apType: "aws_policy"},
		"policy:marketing_policy":            {whoAps: []string{"role:MarketingRole"}, name: "marketing_policy", whatDos: []string{"raito-data-corporate/marketing"}, whatPermissions: []string{"s3:GetObject", "s3:PutObject"}, incomplete: false, apType: "aws_policy"},
	}

	s.NoError(err)
	s.verifyAps(handler, expectedAps)
}

func (s *DataAccessFromTargetTestSuite) verifyAps(handler *mocks.SimpleAccessProviderHandler, expectedAps map[string]expectedAP) {
	for _, ap := range handler.AccessProviders {
		if expected, ok := expectedAps[ap.ExternalId]; ok {
			s.Assert().Equal(expected.name, ap.Name)

			s.Assert().Len(expected.whoUsers, len(ap.Who.Users))
			if expected.whoUsers != nil {
				s.Assert().ElementsMatch(expected.whoUsers, ap.Who.Users)
			}

			s.Assert().Len(expected.whoGroups, len(ap.Who.Groups))
			if expected.whoGroups != nil {
				s.Assert().ElementsMatch(expected.whoGroups, ap.Who.Groups)
			}

			s.Assert().Len(expected.whoAps, len(ap.Who.AccessProviders))
			if expected.whoAps != nil {
				s.Assert().ElementsMatch(expected.whoAps, ap.Who.AccessProviders)
			}

			if expected.whatDos != nil {
				dos, perm := flattenWhat(ap.What)
				s.Assert().ElementsMatch(expected.whatDos, dos)
				s.Assert().ElementsMatch(expected.whatPermissions, perm)
			}

			if expected.incomplete {
				s.Assert().True(ap.Incomplete != nil && *ap.Incomplete)
			} else {
				s.Assert().True(ap.Incomplete == nil || !*ap.Incomplete)
			}

			delete(expectedAps, ap.ExternalId)
		}
	}

	s.Assert().Empty(expectedAps)
}

func flattenWhat(what []sync_from_target.WhatItem) ([]string, []string) {
	var dos, permissions []string
	for _, item := range what {
		dos = append(dos, item.DataObject.FullName)
		permissions = append(permissions, item.Permissions...)
	}

	return dos, permissions
}

type expectedAP struct {
	name            string
	whoUsers        []string
	whoGroups       []string
	whoAps          []string
	whatDos         []string
	whatPermissions []string
	incomplete      bool
	apType          string
}
