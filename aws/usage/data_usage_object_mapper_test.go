package usage

import (
	"reflect"
	"testing"

	"github.com/raito-io/cli/base/data_source"
	"github.com/raito-io/cli/base/data_usage"

	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils/trie"
)

func TestFileUsageObjectMapper_MapObject(t *testing.T) {
	type fields struct {
		pathDepth           int
		dataObjectsWithType *trie.Trie[string]
	}
	type args struct {
		object string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *data_usage.UsageDataObjectReference
	}{
		{
			name: "Fullname can be used",
			fields: fields{
				pathDepth:           10,
				dataObjectsWithType: trie.FromMap("/", map[string]string{"bucket1/folder1/folder2/file1": data_source.File, "bucket1/folder1/folder2/file2": data_source.File, "bucket1/folder1/folder2": data_source.Folder, "bucket1/folder1": data_source.Folder}),
			},
			args: args{
				object: "bucket1/folder1/folder2/file1",
			},
			want: &data_usage.UsageDataObjectReference{
				FullName: "bucket1/folder1/folder2/file1",
				Type:     data_source.File,
			},
		},
		{
			name: "Trim path",
			fields: fields{
				pathDepth:           2,
				dataObjectsWithType: trie.FromMap("/", map[string]string{"bucket1/folder2": data_source.Folder, "bucket1/folder1": "folder", "bucket2/folder1": data_source.Folder}),
			},
			args: args{
				object: "bucket1/folder1/folder2/file1",
			},
			want: &data_usage.UsageDataObjectReference{
				FullName: "bucket1/folder1",
				Type:     data_source.Folder,
			},
		},
		{
			name: "Not found",
			fields: fields{
				pathDepth:           2,
				dataObjectsWithType: trie.FromMap("/", map[string]string{"bucket1/folder2": data_source.Folder, "bucket1/folder1": "folder", "bucket2/folder1": data_source.Folder}),
			},
			args: args{
				object: "bucket4/folder1/folder2/file1",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := FileUsageObjectMapper{
				pathDepth:           tt.fields.pathDepth,
				dataObjectsWithType: tt.fields.dataObjectsWithType,
			}
			if got := m.MapObject(tt.args.object); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MapObject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGlueUsageObjectMapper_MapObject(t *testing.T) {
	type fields struct {
		dataObjectsWithType *trie.Trie[string]
	}
	type args struct {
		object string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *data_usage.UsageDataObjectReference
	}{
		{
			name: "Fullname can be used",
			fields: fields{
				dataObjectsWithType: trie.FromMap("/", map[string]string{"bucket1/folder1/folder2": model.GlueTableType, "bucket1/folder1/folder3": model.GlueTableType, "bucket1/folder1": data_source.Folder}),
			},
			args: args{
				object: "bucket1/folder1/folder2",
			},
			want: &data_usage.UsageDataObjectReference{
				FullName: "bucket1/folder1/folder2",
				Type:     model.GlueTableType,
			},
		},
		{
			name: "Map to table",
			fields: fields{
				dataObjectsWithType: trie.FromMap("/", map[string]string{"bucket1/folder1/folder2": model.GlueTableType, "bucket1/folder1/folder3": model.GlueTableType, "bucket1/folder1": data_source.Folder}),
			},
			args: args{
				object: "bucket1/folder1/folder2/folder3/file.parquet",
			},
			want: &data_usage.UsageDataObjectReference{
				FullName: "bucket1/folder1/folder2",
				Type:     model.GlueTableType,
			},
		},
		{
			name: "Not found",
			fields: fields{
				dataObjectsWithType: trie.FromMap("/", map[string]string{"bucket1/folder1/folder2": model.GlueTableType, "bucket1/folder1/folder3": model.GlueTableType, "bucket1/folder1": data_source.Folder}),
			},
			args: args{
				object: "bucket3/folder1/folder2/folder3/file.parquet",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := GlueUsageObjectMapper{
				dataObjectsWithType: tt.fields.dataObjectsWithType,
			}
			if got := m.MapObject(tt.args.object); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MapObject() = %v, want %v", got, tt.want)
			}
		})
	}
}
