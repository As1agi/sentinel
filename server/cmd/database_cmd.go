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

// todo clean up this sub sections dude
var databaseCmd = &cobra.Command{
	Use:   "database",
	Short: "database",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		//func to pass flags and determine operation as pre-run , maybe use a bitmap or sth
		if (populate_nvd || populate_osv) && !populate {
			return fmt.Errorf("invalid flag config , use the -p flag to populate")
		}

		if !populate {
			return fmt.Errorf("please specify an action (e.g., -p --nvd or database -p)")
		}
		//for now we do this we shall arrange em later I suppose
		if migrate {
			database.InitSchema()
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
			if err = normalizeReadAllCveIntoDataBase(db); err != nil {
				log.Fatal(err)
			}
		} else if runNVD {
			if err = normalizeReadNvdDataIntoDB(db); err != nil {
				log.Fatal(err)
			}
		} else if runOSV {
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
	var err error
	normalizedOsvSavePath, err := config.GetNormalizedCveJsonPath("nvd")
	if err != nil {
		return err
	}
	nvdBaseDir, err := config.GetDatasetRawCveDir("nvd")
	if err != nil {
		return fmt.Errorf("getting source dir: %w", err)
	}
	if !skipNormalize {
		//log.Printf("nvd base dir %v", nvdBaseDir)
		err = dataset.NvdNormalize(nvdBaseDir, normalizedOsvSavePath)
		if err != nil {
			return err
		}
	}

	err = database.ReadNormalizeCveIntoDataBase(db, normalizedOsvSavePath)
	if err != nil {
		return err
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

	if !skipNormalize {
		err = dataset.OsvNormalize(osvBaseDir, normalizedOsvSavePath)
		if err != nil {
			return err
		}
	}

	err = database.ReadNormalizeCveIntoDataBase(db, normalizedOsvSavePath)
	if err != nil {
		return err
	}
	return nil
}
