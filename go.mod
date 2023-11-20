module github.com/raito-io/cli-plugin-aws-account

go 1.21

toolchain go1.21.0

require (
	github.com/aws/aws-sdk-go-v2 v1.22.1
	github.com/aws/aws-sdk-go-v2/config v1.22.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.19.0
	github.com/aws/aws-sdk-go-v2/service/identitystore v1.16.13
	github.com/aws/aws-sdk-go-v2/service/s3 v1.30.0
	github.com/aws/aws-sdk-go-v2/service/ssoadmin v1.16.12
	github.com/aws/smithy-go v1.16.0
	github.com/gammazero/workerpool v1.1.3
	github.com/hashicorp/go-hclog v1.5.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/n4ch04/aws-policy v1.0.1
	github.com/raito-io/cli v0.54.1
	github.com/raito-io/golang-set v0.0.4
	github.com/stretchr/testify v1.8.4
	github.com/vektra/mockery/v2 v2.36.1
)

require (
	github.com/Masterminds/semver/v3 v3.2.1 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.4.10 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.15.1 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.14.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.2.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.5.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.5.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.0.18 // indirect
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.30.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.9.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.1.22 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.10.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.13.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.17.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.19.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.25.0 // indirect
	github.com/bcicen/jstream v1.0.1 // indirect
	github.com/chigopher/pathlib v1.0.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/fatih/color v1.15.0 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/gammazero/deque v0.2.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/uuid v1.3.1 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-plugin v1.5.2 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hashicorp/yamux v0.1.1 // indirect
	github.com/hasura/go-graphql-client v0.10.0 // indirect
	github.com/huandu/xstrings v1.4.0 // indirect
	github.com/iancoleman/strcase v0.3.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jinzhu/copier v0.4.0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/pelletier/go-toml/v2 v2.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rs/zerolog v1.30.0 // indirect
	github.com/sagikazarmark/locafero v0.3.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.10.0 // indirect
	github.com/spf13/cast v1.5.1 // indirect
	github.com/spf13/cobra v1.8.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.17.0 // indirect
	github.com/stretchr/objx v0.5.1 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.9.0 // indirect
	golang.org/x/exp v0.0.0-20230905200255-921286631fa9 // indirect
	golang.org/x/mod v0.12.0 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/term v0.13.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	golang.org/x/tools v0.13.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230920204549-e6e6cdab5c13 // indirect
	google.golang.org/grpc v1.59.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	nhooyr.io/websocket v1.8.10 // indirect
)
