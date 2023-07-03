package aws

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestOrgAccess_ConvertName(t *testing.T) {
	assert.Equal(t, "BLAH", toPermissionSetName("role/AWSReservedSSO_BLAH_123456"))

	assert.Equal(t, "Blah", toPermissionSetName("role/AWSReservedSSO_Blah_123456"))

	assert.Equal(t, "", toPermissionSetName("role/AWS"))

	assert.Equal(t, "", toPermissionSetName("role/AWSReservedSSO_BLAH"))

	assert.Equal(t, "", toPermissionSetName("role/AWSReservedSSOBLAH"))
}
