//go:build integration

package it

import (
	"context"
	"fmt"
	"strings"
	"testing"

	awspolicy "github.com/n4ch04/aws-policy"
	"github.com/raito-io/cli-plugin-aws-account/aws/iam"
	baseit "github.com/raito-io/cli-plugin-aws-account/aws/it"
	"github.com/stretchr/testify/suite"
)

type IAMAccessPointsTestSuite struct {
	baseit.AWSTestSuite
	repo *iam.AwsIamRepository
}

func TestIAMAccessPointsTestSuite(t *testing.T) {
	ts := IAMAccessPointsTestSuite{}
	config := ts.GetConfig()
	repo := iam.NewAwsIamRepository(config)

	ts.repo = repo
	suite.Run(t, &ts)
}

func (s *IAMAccessPointsTestSuite) TestIAMPolicies_ListAccessPoints() {
	accessPoints, err := s.repo.ListAccessPoints(context.Background())
	s.Assert().NoError(err)
	s.Assert().Len(accessPoints, 1)
	s.Assert().Equal("operations", accessPoints[0].Name)
	s.Assert().Equal("raito-corporate-data", accessPoints[0].Bucket)
	s.Assert().Len(accessPoints[0].PolicyParsed.Statements, 1)
	s.Assert().Equal(accessPoints[0].PolicyParsed.Statements[0].Effect, "Allow")
	s.Assert().ElementsMatch([]string{"s3:GetObject"}, accessPoints[0].PolicyParsed.Statements[0].Action)
	s.Assert().True(strings.HasSuffix(accessPoints[0].PolicyParsed.Statements[0].Resource[0], "/object/operations/*"))
	s.Assert().ElementsMatch([]string{"arn:aws:iam::077954824694:user/m_carissa", "arn:aws:iam::077954824694:role/MarketingRole"}, accessPoints[0].PolicyParsed.Statements[0].Principal["AWS"])

	who, what, incomplete := iam.CreateWhoAndWhatFromAccessPointPolicy(accessPoints[0].PolicyParsed, accessPoints[0].Bucket, accessPoints[0].Name, s.GetConfig())
	s.Assert().False(incomplete)

	s.Assert().Len(who.Groups, 0)
	s.Assert().Len(who.AccessProviders, 1)
	s.Assert().Equal(who.AccessProviders[0], "role:MarketingRole")
	s.Assert().Len(who.Users, 1)
	s.Assert().Equal(who.Users[0], "m_carissa")

	s.Assert().Len(what, 1)
	s.Assert().Equal("raito-corporate-data/operations", what[0].DataObject.FullName)
	s.Assert().ElementsMatch([]string{"s3:GetObject"}, what[0].Permissions)
}

func (s *IAMAccessPointsTestSuite) TestIAMPolicies_CreateAccessPoint() {
	name := "int-test-ap1"
	err := s.repo.CreateAccessPoint(context.Background(), name, "raito-corporate-data", awspolicy.Statement{
		Effect:   "Allow",
		Action:   []string{"s3:GetObject", "s3:PutObject"},
		Resource: []string{fmt.Sprintf("arn:aws:s3:eu-central-1:077954824694:accesspoint/%s/object/operations/*", name)},
		Principal: map[string][]string{
			"AWS": {"arn:aws:iam::077954824694:user/d_hayden", "arn:aws:iam::077954824694:role/MarketingRole"},
		},
	})

	s.Assert().NoError(err)

	defer func() {
		err = s.repo.DeleteAccessPoint(context.Background(), name)
		s.Assert().NoError(err)
	}()

	accessPoints, err := s.repo.ListAccessPoints(context.Background())
	s.Assert().NoError(err)

	found := false
	for _, accessPoint := range accessPoints {
		if accessPoint.Name == name {
			found = true
			s.Assert().Equal("raito-corporate-data", accessPoints[0].Bucket)
			s.Assert().Len(accessPoint.PolicyParsed.Statements, 1)
			s.Assert().Equal(accessPoint.PolicyParsed.Statements[0].Effect, "Allow")
			s.Assert().ElementsMatch([]string{"s3:GetObject", "s3:PutObject"}, accessPoint.PolicyParsed.Statements[0].Action)
			s.Assert().True(strings.HasSuffix(accessPoint.PolicyParsed.Statements[0].Resource[0], "object/operations/*"))
			s.Assert().ElementsMatch([]string{"arn:aws:iam::077954824694:user/d_hayden", "arn:aws:iam::077954824694:role/MarketingRole"}, accessPoint.PolicyParsed.Statements[0].Principal["AWS"])
			break
		}
	}

	s.Assert().True(found)
}
