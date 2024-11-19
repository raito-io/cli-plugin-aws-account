//go:build integration

package it

import (
	"context"
	"testing"

	"github.com/raito-io/cli/base/access_provider/sync_from_target"
	"github.com/raito-io/cli/base/wrappers/mocks"
	"github.com/stretchr/testify/suite"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/data_access"
	"github.com/raito-io/cli-plugin-aws-account/aws/it"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
)

type DataAccessFromTargetTestSuite struct {
	it.AWSTestSuite
}

func TestDataAccessFromTargetTestSuiteTestSuite(t *testing.T) {
	ts := DataAccessFromTargetTestSuite{}

	suite.Run(t, &ts)
}

func (s *DataAccessFromTargetTestSuite) TestAccessSyncer_FetchS3AccessPointAccessProviders() {
	accessSyncer := data_access.NewDataAccessSyncerFromConfig(s.GetConfig())

	aps, err := accessSyncer.FetchS3AccessPointAccessProviders(context.Background(), s.GetConfig(), nil)
	s.NoError(err)
	s.GreaterOrEqual(len(aps), 1)

	found := false

	for i, ap := range aps {
		if ap.ApInput.Name != "operations" {
			continue
		}

		s.Equal("operations", aps[i].ApInput.Name)
		s.Equal("operations", aps[i].ApInput.ActualName)
		s.Equal(string(model.AccessPoint), *aps[i].ApInput.Type)
		s.Equal(sync_from_target.Grant, aps[i].ApInput.Action)
		s.Len(aps[i].ApInput.Who.Users, 1)
		s.Equal(aps[i].ApInput.Who.Users[0], "m_carissa")
		s.Len(aps[i].ApInput.Who.AccessProviders, 1)
		s.Equal(constants.RoleTypePrefix+"MarketingRole", aps[i].ApInput.Who.AccessProviders[0])
		s.Equal("077954824694:eu-central-1:raito-data-corporate/operations", aps[i].ApInput.What[0].DataObject.FullName)
		s.Equal("s3:GetObject", aps[i].ApInput.What[0].Permissions[0])
		s.True(aps[i].ApInput.Incomplete == nil || !*aps[0].ApInput.Incomplete)

		found = true
	}

	s.True(found)
}

func (s *DataAccessFromTargetTestSuite) TestAccessSyncer_FetchTest() {
	accessSyncer := data_access.NewDataAccessSyncerFromConfig(s.GetConfig())

	handler := mocks.NewSimpleAccessProviderHandler(s.T(), 100)
	config := s.GetConfig()
	// Skipping AWS managed policies for performance reasons
	config.Parameters[constants.AwsAccessManagedPolicyExcludes] = "Amazon.+,AWS.+"
	config.Parameters[constants.AwsAccessSkipAWSManagedPolicies] = "true"
	err := accessSyncer.SyncAccessProvidersFromTarget(context.Background(), handler, config)

	doPrefix := "077954824694:eu-central-1:"

	expectedAps := map[string]expectedAP{
		"accesspoint:arn:aws:s3:eu-central-1:077954824694:accesspoint/operations": {whoUsers: []string{"m_carissa"}, whoAps: []string{"role:MarketingRole"}, name: "operations", whatDos: []string{doPrefix + "raito-data-corporate/operations"}, whatPermissions: []string{"s3:GetObject"}, incomplete: false, apType: "aws_access_point"},
		"role:MarketingRole":                 {whoUsers: []string{"m_carissa"}, name: "MarketingRole", incomplete: false, apType: "aws_role"},
		"user:d_hayden|inline:DustinPolicy|": {whoUsers: []string{"d_hayden"}, name: "User d_hayden inline policies", whatDos: []string{doPrefix + "raito-data-corporate/operations"}, whatPermissions: []string{"s3:GetObject"}, incomplete: false, apType: "aws_policy"},
		"group:Sales|inline:SalesPolicy|":    {whoGroups: []string{"Sales"}, name: "Group Sales inline policies", whatDos: []string{doPrefix + "raito-data-corporate/sales"}, whatPermissions: []string{"s3:GetObject", "s3:PutObject"}, incomplete: false, apType: "aws_policy"},
		"policy:marketing_policy":            {whoAps: []string{"role:MarketingRole"}, name: "marketing_policy", whatDos: []string{doPrefix + "raito-data-corporate/marketing"}, whatPermissions: []string{"s3:GetObject", "s3:PutObject"}, incomplete: false, apType: "aws_policy"},
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
