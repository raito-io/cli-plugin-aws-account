package trie

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
