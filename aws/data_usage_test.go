package aws

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDataUsage_mapToClosedObject(t *testing.T) {
	availableObjects := map[string]interface{}{
		"bucket": map[string]interface{}{
			"topfolder1": map[string]interface{}{
				"subfolder11": map[string]interface{}{
					"subfolder111": map[string]interface{}{},
				},
				"subfolder12": map[string]interface{}{},
			},
			"topfolder2": map[string]interface{}{},
		},
	}

	tests := map[string]string{
		"bucket/topfolder1/subfolder11/subfolder111":                  "bucket/topfolder1/subfolder11/subfolder111",
		"bucket/topfolder1/subfolder11/subfolder111/myfile.parquet":   "bucket/topfolder1/subfolder11/subfolder111",
		"bucket/topfolder1/subfolder11/subfolder111/another/file.csv": "bucket/topfolder1/subfolder11/subfolder111",
		"bucket/topfolder1/subfolder11/subf/fileke":                   "bucket/topfolder1/subfolder11",
		"bucket/totallydifferent":                                     "bucket",
		"bucket/topfolder2/subfolder11/subfolder111":                  "bucket/topfolder2",
		"whatnow": "",
	}

	for input, expected := range tests {
		t.Run(input, func(t *testing.T) {
			actual := mapToClosedObject(input, availableObjects)
			assert.Equal(t, expected, actual)
		})
	}
}
