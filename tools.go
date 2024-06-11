//go:build tools
// +build tools

package main

import (
	_ "github.com/vektra/mockery/v2"

	_ "github.com/raito-io/enumer"

	_ "github.com/aws/aws-sdk-go-v2/service/secretsmanager" // Required for usage generation
)
