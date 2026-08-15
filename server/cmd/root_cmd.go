/*
Copyright © 2026 NAME HERE asiagijoseph1@gmail.com
*/
package cmd

import (
	"log"
	"os"
	"server/internals/config"

	"github.com/spf13/cobra"
)

var (
	port                                 string
	populate, populate_nvd, populate_osv bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cassandra",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	if err := config.InitDirectories(); err != nil {
		log.Fatal(err)
	}
	rootCmd.AddCommand(databaseCmd)
	rootCmd.AddCommand(serverCmd)
	//database flags
	databaseCmd.Flags().BoolVarP(&populate, "populate", "p", false, "populate")
	databaseCmd.Flags().BoolVar(&populate_nvd, "nvd", false, "nvd")
	databaseCmd.Flags().BoolVar(&populate_osv, "osv", false, "osv")

	//server flags
	serverCmd.Flags().StringVarP(&port, "port", "p", "8080", "")
}
