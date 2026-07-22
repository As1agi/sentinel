package cmd

import (
	"server/internals/server"

	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use: "server",
	RunE: func(cmd *cobra.Command, args []string) error {
		if port != "nil" {
			server.Serve(port)
		} else {
			server.Serve("8080")
		}
		return nil
	}}
