package cmd

import (
	"fmt"
	"path"
	"server/internals/config"
	"server/internals/database"

	"github.com/spf13/cobra"
)

var databaseCmd = &cobra.Command{
	Use:   "database",
	Short: "database",
	RunE: func(cmd *cobra.Command, args []string) error {

		if populate {
			db := database.OpenDB()
			defer db.Close()
			projectPaths, err := config.ResolvePaths()
			if err != nil {
				return err
			}
			//the directory for the OSV data
			sourceDir := path.Join(projectPaths.CveDataPath, "osv")
			//todo use viper for path management and shit and add command for migrate
			database.ReadCVEIntoDataBase(db, sourceDir)
			return nil
		}
		//no commands provided
		if !populate {
			return fmt.Errorf("no commands provided")
		}
		return fmt.Errorf("error invalid commands")
	}}
