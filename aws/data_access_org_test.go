package aws

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestOrgAccess_ConvertName(t *testing.T) {
	assert.Equal(t, "BLAH", toPermissionSetName("AWSReservedSSO_BLAH_123456"))

	assert.Equal(t, "Blah", toPermissionSetName("AWSReservedSSO_Blah_123456"))

	assert.Equal(t, "", toPermissionSetName("AWS"))

	assert.Equal(t, "", toPermissionSetName("AWSReservedSSO_BLAH"))

	assert.Equal(t, "", toPermissionSetName("AWSReservedSSOBLAH"))
}
