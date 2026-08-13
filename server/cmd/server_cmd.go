package cmd

import (
	"server/internals/config"
	"server/internals/server"

	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use: "server",
	RunE: func(cmd *cobra.Command, args []string) error {

		dbPath, err := config.GetDBPath()
		if err != nil {
			return err
		}

		if port != "nil" {
			server.Serve(port, dbPath)
		} else {

			server.Serve("8080", dbPath)
		}
		return nil
	}}
