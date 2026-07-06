package main

import (
	"log"
	"path"
	"server/internals/config"
	"server/internals/database"
	dataset "server/internals/datasets"
)

func main() {
	//get the root path
	Path, err := config.ResolvePaths()
	if err != nil {
		log.Fatalf("%v\n", err)
	}

	db := database.OpenDB()
	defer db.Close()
	CVEDataPath := path.Join(Path.Root, "data", "cve.json")

	//todo add a time elapsed message
	database.ReadCVEIntoDataBase(db, CVEDataPath)
	log.Println("Done reading the existing data into DB")

	err = dataset.CleanOSV(CVEDataPath)
	if err != nil {
		log.Printf("Error cleaning OSV data , %v\n", err)
	}

}
