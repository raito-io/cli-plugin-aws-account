package permissions

import ds "github.com/raito-io/cli/base/data_source"

var writeUsage = []string{ds.Write}
var adminUsage = []string{ds.Admin}
var readUsage = []string{ds.Read}

var readGlobalPermissions = ds.ReadGlobalPermission().StringValues()
var writeGlobalPermissions = ds.WriteGlobalPermission().StringValues()
var adminGlobalPermissions = ds.AdminGlobalPermission().StringValues() //nolint:unused // defined for future references
