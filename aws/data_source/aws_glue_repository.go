package data_source

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/smithy-go/ptr"
	"github.com/raito-io/cli-plugin-aws-account/aws/model"
	"github.com/raito-io/cli/base/util/config"

	baserepo "github.com/raito-io/cli-plugin-aws-account/aws/repo"
	"github.com/raito-io/cli-plugin-aws-account/aws/utils"
)

type AwsGlueRepository struct {
	configMap *config.ConfigMap
}

func NewAwsGlueRepository(configMap *config.ConfigMap) *AwsGlueRepository {
	return &AwsGlueRepository{
		configMap: configMap,
	}
}

func (repo *AwsGlueRepository) GetGlueClient(ctx context.Context, region *string) (*glue.Client, error) {
	cfg, err := baserepo.GetAWSConfig(ctx, repo.configMap, region)

	if err != nil {
		log.Fatalf("failed to load configuration, %v", err)
	}

	client := glue.NewFromConfig(cfg)

	return client, nil
}

func (repo *AwsGlueRepository) ListTablesForDatabase(ctx context.Context, accountId string, database string, region string) ([]model.GlueTable, error) {
	client, err := repo.GetGlueClient(ctx, ptr.String(region))
	if err != nil {
		return nil, err
	}

	moreObjectsAvailable := true

	var nextToken *string

	tables := make([]model.GlueTable, 0, 10)

	for moreObjectsAvailable {
		utils.Logger.Debug(fmt.Sprintf("Load more glue tables for database %q", database))

		tbls, err2 := client.GetTables(ctx, &glue.GetTablesInput{
			NextToken:    nextToken,
			CatalogId:    &accountId,
			DatabaseName: &database,
		})

		if err2 != nil {
			return nil, fmt.Errorf("failed to list tables for database %q: %w", database, err2)
		}

		// TODO table filtering based on config
		for i := range tbls.TableList {
			tbl := tbls.TableList[i]
			if tbl.StorageDescriptor != nil && tbl.StorageDescriptor.Location != nil {
				table := model.GlueTable{
					Name:        *tbl.Name,
					Location:    *tbl.StorageDescriptor.Location,
					Columns:     make([]model.GlueColumn, 0, len(tbl.StorageDescriptor.Columns)),
					Description: tbl.Description,
					Tags:        tbl.Parameters,
				}

				for _, col := range tbl.StorageDescriptor.Columns {
					table.Columns = append(table.Columns, model.GlueColumn{
						Name:        *col.Name,
						Type:        col.Type,
						Description: col.Comment,
						Tags:        col.Parameters,
					})
				}

				tables = append(tables, table)
			}
		}

		nextToken = tbls.NextToken
		moreObjectsAvailable = nextToken != nil
	}

	return tables, nil
}

func (repo *AwsGlueRepository) ListDatabases(ctx context.Context, accountId string, region string) ([]string, error) {
	client, err := repo.GetGlueClient(ctx, ptr.String(region))
	if err != nil {
		return nil, err
	}

	moreObjectsAvailable := true

	var nextToken *string

	databases := make([]string, 0, 10)

	for moreObjectsAvailable {
		utils.Logger.Debug(fmt.Sprintf("Load more glue databases for account %q in region %q", accountId, region))

		dbs, err2 := client.GetDatabases(ctx, &glue.GetDatabasesInput{
			NextToken: nextToken,
			CatalogId: &accountId,
		})

		if err2 != nil {
			return nil, fmt.Errorf("failed to list databases: %w", err2)
		}

		// TODO database filtering based on config
		for _, db := range dbs.DatabaseList {
			databases = append(databases, *db.Name)
		}

		nextToken = dbs.NextToken
		moreObjectsAvailable = nextToken != nil
	}

	return databases, nil
}
