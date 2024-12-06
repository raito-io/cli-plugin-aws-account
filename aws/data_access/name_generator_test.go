package data_access

import (
	"testing"

	"github.com/raito-io/cli/base/access_provider/sync_to_target"
	"github.com/stretchr/testify/require"

	"github.com/raito-io/cli-plugin-aws-account/aws/constants"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/mocks/naming_hint"
)

func TestNameGenerator_GenerateName(t *testing.T) {
	testAp := sync_to_target.AccessProvider{Name: "someAp"}
	type fields struct {
		accountId string
		setup     func(accessPointNameGenerator *naming_hint.MockUniqueGenerator, regularNameGenerator *naming_hint.MockUniqueGenerator, ssoNameGenerator *naming_hint.MockUniqueGenerator)
	}
	type args struct {
		ap     *sync_to_target.AccessProvider
		apType model.AccessProviderType
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "AccessPoint",
			fields: fields{
				accountId: "123456789012",
				setup: func(accessPointNameGenerator *naming_hint.MockUniqueGenerator, regularNameGenerator *naming_hint.MockUniqueGenerator, ssoNameGenerator *naming_hint.MockUniqueGenerator) {
					accessPointNameGenerator.EXPECT().Generate(&testAp).Return("access-point-name", nil)
				},
			},
			args: args{
				ap:     &testAp,
				apType: model.AccessPoint,
			},
			want:    "access-point-name",
			wantErr: false,
		},
		{
			name: "SSORole",
			fields: fields{
				accountId: "123456789012",
				setup: func(accessPointNameGenerator *naming_hint.MockUniqueGenerator, regularNameGenerator *naming_hint.MockUniqueGenerator, ssoNameGenerator *naming_hint.MockUniqueGenerator) {
					ssoNameGenerator.EXPECT().Generate(&testAp).Return("regular-name", nil)
				},
			},
			args: args{
				ap:     &testAp,
				apType: model.SSORole,
			},
			want:    constants.SsoRolePrefix + "regular-name_123456789012",
			wantErr: false,
		},
		{
			name: "Role",
			fields: fields{
				accountId: "123456789012",
				setup: func(accessPointNameGenerator *naming_hint.MockUniqueGenerator, regularNameGenerator *naming_hint.MockUniqueGenerator, ssoNameGenerator *naming_hint.MockUniqueGenerator) {
					regularNameGenerator.EXPECT().Generate(&testAp).Return("regular-name", nil)
				},
			},
			args: args{
				ap:     &testAp,
				apType: model.Role,
			},
			want:    "regular-name",
			wantErr: false,
		},
		{
			name: "Policy",
			fields: fields{
				accountId: "123456789012",
				setup: func(accessPointNameGenerator *naming_hint.MockUniqueGenerator, regularNameGenerator *naming_hint.MockUniqueGenerator, ssoNameGenerator *naming_hint.MockUniqueGenerator) {
					regularNameGenerator.EXPECT().Generate(&testAp).Return("regular-name", nil)
				},
			},
			args: args{
				ap:     &testAp,
				apType: model.Policy,
			},
			want:    "regular-name",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			accessPointNameGenerator := naming_hint.NewMockUniqueGenerator(t)
			regularNameGenerator := naming_hint.NewMockUniqueGenerator(t)
			ssoRoleNameGenerator := naming_hint.NewMockUniqueGenerator(t)

			tt.fields.setup(accessPointNameGenerator, regularNameGenerator, ssoRoleNameGenerator)
			nameGenerator := NameGenerator{
				accountId:                tt.fields.accountId,
				accessPointNameGenerator: accessPointNameGenerator,
				regularNameGenerator:     regularNameGenerator,
				roleNameGenerator:        ssoRoleNameGenerator,
			}

			// When
			got, err := nameGenerator.GenerateName(tt.args.ap, tt.args.apType)

			// Then
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestNameGenerator_GenerateActualName(t *testing.T) {
	nameGenerator, err := NewNameGenerator("1234")
	require.NoError(t, err)

	name, err := nameGenerator.GenerateName(&sync_to_target.AccessProvider{Name: "someAp", NamingHint: "policy/CustomAccess"}, model.Policy)
	require.NoError(t, err)
	require.Equal(t, "policy_CustomAccess", name)
}
