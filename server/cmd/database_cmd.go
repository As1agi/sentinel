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
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if (populate_nvd || populate_osv) && !populate {
			return fmt.Errorf("invalid flag config , use the -p flag to populate")
		}

		if !populate {
			return fmt.Errorf("please specify an action (e.g., -p --nvd or database -p)")
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		runNVD := populate_nvd || (!populate_nvd && !populate_osv)
		runOSV := populate_osv || (!populate_nvd && !populate_osv)

		db := database.OpenDB()
		defer func() {
			if dbCloseErr := db.Close(); dbCloseErr != nil {
				if dbCloseErr != nil {
					err = fmt.Errorf("error closing database :%v/t", dbCloseErr)
				}
			}
		}()

		if runNVD && runOSV {
			log.Printf("normalizing both")
			if err = normalizeReadAllCveIntoDataBase(db); err != nil {
				log.Fatal(err)
			}
		} else if runNVD {
			log.Printf("normalizing nvd")
			if err = normalizeReadNvdDataIntoDB(db); err != nil {
				log.Fatal(err)
			}
		} else if runOSV {
			log.Printf("normalizing osv")
			if err := normalizeReadOsvDataIntoDB(db); err != nil {
				log.Fatal(err)
			}
		}

		return nil
	}}

func normalizeReadAllCveIntoDataBase(db *sql.DB) error {
	if err := normalizeReadOsvDataIntoDB(db); err != nil {
		return err
	}

	if err := normalizeReadNvdDataIntoDB(db); err != nil {
		return err
	}
	return nil
}

func normalizeReadNvdDataIntoDB(db *sql.DB) error {
	normalizedOsvSavePath, err := config.GetNormalizedCveJsonPath("nvd")
	if err != nil {
		return err
	}

	nvdBaseDir, err := config.GetDatasetRawCveDir("nvd")
	if err != nil {
		return fmt.Errorf("getting source dir: %w", err)
	}
	log.Printf("nvd base dir %v", nvdBaseDir)
	err = dataset.NvdNormalize(nvdBaseDir, normalizedOsvSavePath)
	if err != nil {
		return err
	}
	//todo add normalize func here
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
