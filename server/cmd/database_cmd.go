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

			if err = CleanReadAllCveIntoDataBase(db); err != nil {
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

func CleanReadAllCveIntoDataBase(db *sql.DB) error {
	//read OSV data
	if err := CleanReadOsvDataIntoDB(db); err != nil {
		log.Fatal(err)
	}
	return nil
}

func CleanReadOsvDataIntoDB(db *sql.DB) error {
	//the directory for the OSV data
	cleanOsvJsonPath, err := config.GetNormalizedCveJsonPath("osv")
	if err != nil {
		return err
	}

	err = dataset.OsvNormalize()
	if err != nil {
		return err
	}

	err = database.ReadNormalizeCveIntoDataBase(db, cleanOsvJsonPath)
	if err != nil {
		return err
	}

	return nil
}
