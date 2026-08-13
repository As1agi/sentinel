package cmd

import (
	"database/sql"
	"fmt"
	"log"
	"server/internals/config"
	"server/internals/database"
	dataset "server/internals/datasets"

	"github.com/spf13/cobra"
)

// todo add command for migrate
var databaseCmd = &cobra.Command{
	Use:   "database",
	Short: "database",
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error
		if populate {
			db := database.OpenDB()
			defer func() {
				if dbCloseErr := db.Close(); dbCloseErr != nil {
					if err == nil {
						err = fmt.Errorf("error closing database :%v/t", dbCloseErr)
					} else {
						log.Printf("error closing database")
					}
				}
			}()

			if err = normalizeReadAllCveIntoDataBase(db); err != nil {
				log.Fatal(err)
			}
			return nil
		}

		//no commands provided
		if !populate {
			return fmt.Errorf("no commands provided")
		}
		return fmt.Errorf("error invalid commands")
	}}

func normalizeReadAllCveIntoDataBase(db *sql.DB) error {
	if err := normalizeReadOsvDataIntoDB(db); err != nil {
		log.Fatal(err)
	}
	return nil
}

func normalizeReadOsvDataIntoDB(db *sql.DB) error {

	normalizedOsvSavePath, err := config.GetNormalizedCveJsonPath("osv")
	if err != nil {
		return err
	}
	osvBaseDir, err := config.GetDatasetRawCveDir("osv")
	if err != nil {
		return fmt.Errorf("getting source dir: %w", err)
	}

	err = dataset.OsvNormalize(osvBaseDir, normalizedOsvSavePath)
	if err != nil {
		return err
	}

	err = database.ReadNormalizeCveIntoDataBase(db, normalizedOsvSavePath)
	if err != nil {
		return err
	}

	return nil
}
