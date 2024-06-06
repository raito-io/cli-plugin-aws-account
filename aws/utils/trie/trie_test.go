package trie

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFromMap(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		trie := FromMap[string]("_", map[string]string{})

		assert.Equal(t, 0, trie.Size())
	})

	t.Run("Non-empty", func(t *testing.T) {
		trie := FromMap[string]("_", map[string]string{
			"AWSAdministratorAccess_533d93b1c83ef85b":           "AWSAdministratorAccess",
			"AWSOrganizationsFullAccess_8f907acb75f8d979":       "AWSOrganizationsFullAccess",
			"AWSReadOnlyAccess_80b3822d57d5269c":                "AWSReadOnlyAccess",
			"RAITO_DataProduct_077954824694_0ba0787139fb31cf":   "RAITO_DataProduct_077954824694",
			"RAITO_DataProduct_459789456148_0ba0787139fb31cf":   "RAITO_DataProduct_459789456148",
			"RAITO_OtherDataProduct_549786428_0ba0747895fb31cf": "RAITO_OtherDataProduct_549786428",
			"OtherRole_with_a_random_Postfix":                   "OtherRole",
		})

		refTree := New[string]("_")
		refTree.Insert("AWSAdministratorAccess_533d93b1c83ef85b", "AWSAdministratorAccess")
		refTree.Insert("AWSOrganizationsFullAccess_8f907acb75f8d979", "AWSOrganizationsFullAccess")
		refTree.Insert("AWSReadOnlyAccess_80b3822d57d5269c", "AWSReadOnlyAccess")
		refTree.Insert("RAITO_DataProduct_077954824694_0ba0787139fb31cf", "RAITO_DataProduct_077954824694")
		refTree.Insert("RAITO_DataProduct_459789456148_0ba0787139fb31cf", "RAITO_DataProduct_459789456148")
		refTree.Insert("RAITO_OtherDataProduct_549786428_0ba0747895fb31cf", "RAITO_OtherDataProduct_549786428")
		refTree.Insert("OtherRole_with_a_random_Postfix", "OtherRole")

		assert.Equal(t, 7, trie.Size())
		assert.True(t, trie.Equal(refTree, func(a string, b string) bool {
			return a == b
		}))
	})

}

func TestTrie_SearchPrefix(t *testing.T) {
	trie := New[string]("_")
	trie.Insert("AWSAdministratorAccess_533d93b1c83ef85b", "AWSAdministratorAccess")
	trie.Insert("AWSOrganizationsFullAccess_8f907acb75f8d979", "AWSOrganizationsFullAccess")
	trie.Insert("AWSReadOnlyAccess_80b3822d57d5269c", "AWSReadOnlyAccess")
	trie.Insert("RAITO_DataProduct_077954824694_0ba0787139fb31cf", "RAITO_DataProduct_077954824694")
	trie.Insert("RAITO_DataProduct_459789456148_0ba0787139fb31cf", "RAITO_DataProduct_459789456148")
	trie.Insert("RAITO_OtherDataProduct_549786428_0ba0747895fb31cf", "RAITO_OtherDataProduct_549786428")
	trie.Insert("OtherRole_with_a_random_Postfix", "OtherRole")

	tests := []struct {
		name   string
		prefix string
		want   []string
	}{
		{
			name:   "AWSAdministratorAccess_533d93b1c83ef85b",
			prefix: "AWSAdministratorAccess_533d93b1c83ef85b",
			want:   []string{"AWSAdministratorAccess"},
		},
		{
			name:   "AWSOrganizationsFullAccess",
			prefix: "AWSOrganizationsFullAccess",
			want:   []string{"AWSOrganizationsFullAccess"},
		},
		{
			name:   "AWSReadOnlyAccess",
			prefix: "AWSReadOnlyAccess",
			want:   []string{"AWSReadOnlyAccess"},
		},
		{
			name:   "RAITO_DataProduct_077954824694",
			prefix: "RAITO_DataProduct_077954824694",
			want:   []string{"RAITO_DataProduct_077954824694"},
		},
		{
			name:   "RAITO_DataProduct",
			prefix: "RAITO_DataProduct",
			want:   []string{"RAITO_DataProduct_077954824694", "RAITO_DataProduct_459789456148"},
		},
		{
			name:   "NonExisting",
			prefix: "NonExisting",
			want:   nil,
		},
		{
			name:   "AWSAdministratorAccess_533d93b1c83ef85b_NonExisting",
			prefix: "AWSAdministratorAccess_533d93b1c83ef85b_NonExisting",
			want:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trie.SearchPrefix(tt.prefix)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestTrie_Size(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		trie := New[string]("_")

		assert.Equal(t, 0, trie.Size())
	})

	t.Run("Non-empty", func(t *testing.T) {
		trie := New[string]("_")
		trie.Insert("AWSAdministratorAccess_533d93b1c83ef85b", "AWSAdministratorAccess")
		trie.Insert("AWSOrganizationsFullAccess_8f907acb75f8d979", "AWSOrganizationsFullAccess")
		trie.Insert("AWSReadOnlyAccess_80b3822d57d5269c", "AWSReadOnlyAccess")
		trie.Insert("RAITO_DataProduct_077954824694_0ba0787139fb31cf", "RAITO_DataProduct_077954824694")
		trie.Insert("RAITO_DataProduct_459789456148_0ba0787139fb31cf", "RAITO_DataProduct_459789456148")
		trie.Insert("RAITO_OtherDataProduct_549786428_0ba0747895fb31cf", "RAITO_OtherDataProduct_549786428")
		trie.Insert("OtherRole_with_a_random_Postfix", "OtherRole")

		assert.Equal(t, 7, trie.Size())
	})
}

func TestTrie_Get(t1 *testing.T) {
	trie := New[string]("_")
	trie.Insert("AWSAdministratorAccess_533d93b1c83ef85b", "AWSAdministratorAccess")
	trie.Insert("AWSOrganizationsFullAccess_8f907acb75f8d979", "AWSOrganizationsFullAccess")
	trie.Insert("AWSReadOnlyAccess_80b3822d57d5269c", "AWSReadOnlyAccess")
	trie.Insert("RAITO_DataProduct_077954824694_0ba0787139fb31cf", "RAITO_DataProduct_077954824694")
	trie.Insert("RAITO_DataProduct_459789456148_0ba0787139fb31cf", "RAITO_DataProduct_459789456148")
	trie.Insert("RAITO_OtherDataProduct_549786428_0ba0747895fb31cf", "RAITO_OtherDataProduct_549786428")
	trie.Insert("OtherRole_with_a_random_Postfix", "OtherRole")

	type testCase struct {
		name   string
		keyArg string
		want   string
		found  bool
	}
	tests := []testCase{
		{
			name:   "Existing key",
			keyArg: "RAITO_DataProduct_077954824694_0ba0787139fb31cf",
			want:   "RAITO_DataProduct_077954824694",
			found:  true,
		},
		{
			name:   "Non-existing key",
			keyArg: "RAITO_DataProduct_077954824694_NonExisting",
			want:   "",
			found:  false,
		},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			got, got1 := trie.Get(tt.keyArg)
			assert.Equalf(t1, tt.want, got, "Get(%v)", tt.keyArg)
			assert.Equalf(t1, tt.found, got1, "Get(%v)", tt.keyArg)
		})
	}
}

func TestTrie_GetClosest(t1 *testing.T) {
	trie := New[string]("_")
	trie.Insert("AWSAdministratorAccess_533d93b1c83ef85b", "AWSAdministratorAccess")
	trie.Insert("AWSOrganizationsFullAccess_8f907acb75f8d979", "AWSOrganizationsFullAccess")
	trie.Insert("AWSReadOnlyAccess_80b3822d57d5269c", "AWSReadOnlyAccess")
	trie.Insert("RAITO_DataProduct_077954824694_0ba0787139fb31cf", "RAITO_DataProduct_077954824694")
	trie.Insert("RAITO_DataProduct_459789456148_0ba0787139fb31cf", "RAITO_DataProduct_459789456148")
	trie.Insert("RAITO_OtherDataProduct_549786428_0ba0747895fb31cf", "RAITO_OtherDataProduct_549786428")
	trie.Insert("OtherRole_with_a_random_Postfix", "OtherRole")

	type testCase struct {
		name      string
		key       string
		wantKey   string
		wantValue string
	}
	tests := []testCase{
		{
			name:      "Existing key",
			key:       "RAITO_DataProduct_077954824694_0ba0787139fb31cf",
			wantKey:   "RAITO_DataProduct_077954824694_0ba0787139fb31cf",
			wantValue: "RAITO_DataProduct_077954824694",
		},
		{
			name:      "Extended key",
			key:       "RAITO_DataProduct_077954824694_0ba0787139fb31cf_AntoherRandomPart_AndAnother",
			wantKey:   "RAITO_DataProduct_077954824694_0ba0787139fb31cf",
			wantValue: "RAITO_DataProduct_077954824694",
		},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			got, got1 := trie.GetClosest(tt.key)
			assert.Equalf(t1, tt.wantKey, got, "GetClosest(%v)", tt.key)
			assert.Equalf(t1, tt.wantValue, got1, "GetClosest(%v)", tt.key)
		})
	}
}

func TestTrie_Equal(t1 *testing.T) {
	type args[T any] struct {
		other *Trie[T]
	}
	type testCase[T any] struct {
		name string
		t    *Trie[T]
		args args[T]
		want bool
	}
	tests := []testCase[string]{
		{
			name: "Empty equal",
			t:    FromMap[string]("_", nil),
			args: args[string]{
				other: FromMap[string]("_", nil),
			},
			want: true,
		},
		{
			name: "Empty not equal",
			t:    FromMap[string]("_", nil),
			args: args[string]{
				other: FromMap[string]("_", map[string]string{"key": "value"}),
			},
			want: false,
		},
		{
			name: "equal",
			t: FromMap[string]("_", map[string]string{
				"AWSAdministratorAccess_533d93b1c83ef85b":           "AWSAdministratorAccess",
				"AWSOrganizationsFullAccess_8f907acb75f8d979":       "AWSOrganizationsFullAccess",
				"AWSReadOnlyAccess_80b3822d57d5269c":                "AWSReadOnlyAccess",
				"RAITO_DataProduct_077954824694_0ba0787139fb31cf":   "RAITO_DataProduct_077954824694",
				"RAITO_DataProduct_459789456148_0ba0787139fb31cf":   "RAITO_DataProduct_459789456148",
				"RAITO_OtherDataProduct_549786428_0ba0747895fb31cf": "RAITO_OtherDataProduct_549786428",
				"OtherRole_with_a_random_Postfix":                   "OtherRole",
			}),
			args: args[string]{
				other: FromMap[string]("_", map[string]string{
					"AWSAdministratorAccess_533d93b1c83ef85b":           "AWSAdministratorAccess",
					"AWSOrganizationsFullAccess_8f907acb75f8d979":       "AWSOrganizationsFullAccess",
					"AWSReadOnlyAccess_80b3822d57d5269c":                "AWSReadOnlyAccess",
					"RAITO_DataProduct_077954824694_0ba0787139fb31cf":   "RAITO_DataProduct_077954824694",
					"RAITO_DataProduct_459789456148_0ba0787139fb31cf":   "RAITO_DataProduct_459789456148",
					"RAITO_OtherDataProduct_549786428_0ba0747895fb31cf": "RAITO_OtherDataProduct_549786428",
					"OtherRole_with_a_random_Postfix":                   "OtherRole",
				}),
			},
			want: true,
		},
		{
			name: "non equal - empty leaf",
			t: FromMap[string]("_", map[string]string{
				"AWSAdministratorAccess_533d93b1c83ef85b":           "AWSAdministratorAccess",
				"AWSOrganizationsFullAccess_8f907acb75f8d979":       "AWSOrganizationsFullAccess",
				"AWSReadOnlyAccess_80b3822d57d5269c":                "AWSReadOnlyAccess",
				"RAITO_DataProduct_077954824694_0ba0787139fb31cf":   "RAITO_DataProduct_077954824694",
				"RAITO_DataProduct_459789456148_0ba0787139fb31cf":   "RAITO_DataProduct_459789456148",
				"RAITO_OtherDataProduct_549786428_0ba0747895fb31cf": "RAITO_OtherDataProduct_549786428",
				"OtherRole_with_a_random_Postfix":                   "OtherRole",
			}),
			args: args[string]{
				other: FromMap[string]("_", map[string]string{
					"AWSAdministratorAccess_533d93b1c83ef85b_1234567":   "AWSAdministratorAccess",
					"AWSOrganizationsFullAccess_8f907acb75f8d979":       "AWSOrganizationsFullAccess",
					"AWSReadOnlyAccess_80b3822d57d5269c":                "AWSReadOnlyAccess",
					"RAITO_DataProduct_077954824694_0ba0787139fb31cf":   "RAITO_DataProduct_077954824694",
					"RAITO_DataProduct_459789456148_0ba0787139fb31cf":   "RAITO_DataProduct_459789456148",
					"RAITO_OtherDataProduct_549786428_0ba0747895fb31cf": "RAITO_OtherDataProduct_549786428",
					"OtherRole_with_a_random_Postfix":                   "OtherRole",
				}),
			},
			want: false,
		},
		{
			name: "non equal - non equal leaf",
			t: FromMap[string]("_", map[string]string{
				"AWSAdministratorAccess_533d93b1c83ef85b":           "AWSAdministratorAccess",
				"AWSOrganizationsFullAccess_8f907acb75f8d979":       "AWSOrganizationsFullAccess",
				"AWSReadOnlyAccess_80b3822d57d5269c":                "AWSReadOnlyAccess",
				"RAITO_DataProduct_077954824694_0ba0787139fb31cf":   "RAITO_DataProduct_077954824694",
				"RAITO_DataProduct_459789456148_0ba0787139fb31cf":   "RAITO_DataProduct_459789456148",
				"RAITO_OtherDataProduct_549786428_0ba0747895fb31cf": "RAITO_OtherDataProduct_549786428",
				"OtherRole_with_a_random_Postfix":                   "OtherRole",
			}),
			args: args[string]{
				other: FromMap[string]("_", map[string]string{
					"AWSAdministratorAccess_533d93b1c83ef85b":           "OtherAWSAdministratorAccess",
					"AWSOrganizationsFullAccess_8f907acb75f8d979":       "AWSOrganizationsFullAccess",
					"AWSReadOnlyAccess_80b3822d57d5269c":                "AWSReadOnlyAccess",
					"RAITO_DataProduct_077954824694_0ba0787139fb31cf":   "RAITO_DataProduct_077954824694",
					"RAITO_DataProduct_459789456148_0ba0787139fb31cf":   "RAITO_DataProduct_459789456148",
					"RAITO_OtherDataProduct_549786428_0ba0747895fb31cf": "RAITO_OtherDataProduct_549786428",
					"OtherRole_with_a_random_Postfix":                   "OtherRole",
				}),
			},
			want: false,
		},
		{
			name: "non equal - other edges",
			t: FromMap[string]("_", map[string]string{
				"AWSAdministratorAccess_533d93b1c83ef85b":           "AWSAdministratorAccess",
				"AWSOrganizationsFullAccess_8f907acb75f8d979":       "AWSOrganizationsFullAccess",
				"AWSReadOnlyAccess_80b3822d57d5269c":                "AWSReadOnlyAccess",
				"RAITO_DataProduct_077954824694_0ba0787139fb31cf":   "RAITO_DataProduct_077954824694",
				"RAITO_DataProduct_459789456148_0ba0787139fb31cf":   "RAITO_DataProduct_459789456148",
				"RAITO_OtherDataProduct_549786428_0ba0747895fb31cf": "RAITO_OtherDataProduct_549786428",
				"OtherRole_with_a_random_Postfix":                   "OtherRole",
			}),
			args: args[string]{
				other: FromMap[string]("_", map[string]string{
					"AWSAdministratorAccess_533d93b1c83ef85b_1234567":   "OtherAWSAdministratorAccess",
					"AWSOrganizationsFullAccess_8f907acb75f8d979":       "AWSOrganizationsFullAccess",
					"RAITO_DataProduct_077954824694_80b3822d57d5269c":   "AWSReadOnlyAccess",
					"RAITO_DataProduct_077954824694_0ba0787139fb31cf":   "RAITO_DataProduct_077954824694",
					"RAITO_DataProduct_459789456148_0ba0787139fb31cf":   "RAITO_DataProduct_459789456148",
					"RAITO_OtherDataProduct_549786428_0ba0747895fb31cf": "RAITO_OtherDataProduct_549786428",
					"OtherRole_with_a_random_Postfix":                   "OtherRole",
				}),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			assert.Equalf(t1, tt.want, tt.t.Equal(tt.args.other, func(a string, b string) bool {
				return a == b
			}), "Equal(%v, ==)", tt.args.other)
		})
	}
}
