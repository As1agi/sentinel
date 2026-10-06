package logic

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"server/internals"
)

type VulnPackage struct {
	PackageName  string                  `json:"package_name"`
	Installed    string                  `json:"installed"`
	Introduced   string                  `json:"introduced"`
	Fixed        string                  `json:"fixed"`
	Purl         string                  `json:"purl"`
	CveId        string                  `json:"CveId"`
	CvssMetricV2 internals.CvssMetricV2  `json:"cvssMetricv2,omitempty"`
	CvssMetricV3 internals.CvssMetricV30 `json:"cvssMetricv3,omitempty"`
}

// AuditUserPackages audits all the packages for a user for vulnerabilities
func AuditUserPackages(hostName string, machineID string, db *sql.DB) ([]VulnPackage, error) {
	var vulnPackages []VulnPackage

	//we need to get X rows of osPackages and create them in a struct the pass them one by one to is vuln package
	//then we create a batch of data 5 vulns to create a transaction then we commit them to another table in the database
	//then the user can just get data from that table for vuln packages

	queryGetUserId := `
	SELECT id from users where hostname = ?
`
	queryGetSbomId := `
	SELECT id,os_ecosystem FROM sboms WHERE (user_id = ? AND machine_id = ?)
`
	queryGetOsPackages := `
	SELECT id,name,version,source_name,source_version FROM packages WHERE sbom_id = ? AND id > ? ORDER BY id LIMIT 25
`
	queryGetMatchingCVEs := `
	SELECT advisory_id,package_name,introduced,fixed,purl,cvssmetric2,cvssmetric3 FROM cve WHERE ecosystem = ? AND (
	    package_name = ? 
	    OR package_name = ?
	)
`
	//map to track vulns which have already been added to the struct
	//reduce false positives when the source name is used to find the vuln
	//key = name/source.name+CVE-ID
	seen := map[string]bool{}

	//prepare the statement for querying the cve table for matching CVE packages
	getMatchingCVEStmt, err := db.Prepare(queryGetMatchingCVEs)
	if err != nil {
		return nil, fmt.Errorf("error preparing statement for fetching matching CVEs , %v", err)
	}
	defer func() {
		_ = getMatchingCVEStmt.Close()
	}()

	var userID int64
	//fist get the userId
	row := db.QueryRow(queryGetUserId, hostName)
	err = row.Scan(&userID)
	if err != nil {
		return []VulnPackage{}, fmt.Errorf("error fetching user ID from database %v", err)
	}

	//then we get the SBOM id for the machine
	var sbomID int64
	var ecosystem string
	row = db.QueryRow(queryGetSbomId, userID, machineID)
	err = row.Scan(&sbomID, &ecosystem)
	if err != nil {
		return []VulnPackage{}, fmt.Errorf("error fetching user sbomID from database %v", err)
	}

	//then we use the SBOM ID to get the packages for the SBOM from the database, marshal them into structs
	//then we perfom ops on them

	//lastID is used to track the last ID for the previous query
	var lastID int
	var vulnCount int
	var checked int
	for {
		var count = 0
		rows, err := db.Query(queryGetOsPackages, sbomID, lastID)
		if err != nil {
			return []VulnPackage{}, fmt.Errorf("error fetching user os packages from database %v", err)
		}

		//loop throught the batch we have and scan for vulns
		for rows.Next() {
			var id int

			var pkg internals.OSPackage
			if err = rows.Scan(
				&id,
				&pkg.Name,
				&pkg.Version,
				&pkg.Source.SourceName,
				&pkg.Source.SourceVersion,
			); err != nil {
				return nil, fmt.Errorf("error scanning rows for SBOM for User: %v machineID: %v  last ID: %v", hostName, machineID, lastID)
			}

			lastID = id
			count++
			// audit package
			vulnPkg, err := IsVulnerablePackage(getMatchingCVEStmt, seen, ecosystem, pkg)
			if err != nil {
				log.Printf("error auditing package %s: %v", pkg.Name, err)
				continue
			}

			if vulnPkg.PackageName == "" {
				continue
			}
			//log.Printf("Found vulnerabilities in package %+v\nFound:1\nVuln Pkg:%+v\n", pkg, vulnPkg)
			vulnPackages = append(vulnPackages, vulnPkg)
			vulnCount++
			//todo later on to prevent nuking our ram, we update the database in batches of 5 vulnPackages at a tim
		}

		if err = rows.Err(); err != nil {
			return []VulnPackage{}, err
		}
		checked += count
		if err := rows.Close(); err != nil {
			return []VulnPackage{}, err
		}
		if count == 0 {
			break
		}
	}

	log.Printf("\nFound %v\n Checked %v\n vuln packages for the User:%v , machineID:%v\n last ID: %v\n", vulnCount, checked, hostName, machineID, lastID)
	return vulnPackages, nil
}

// IsVulnerablePackage checks if a package is vulnerable
func IsVulnerablePackage(stmt *sql.Stmt, seen map[string]bool, ecosystem string, osPackage internals.OSPackage) (VulnPackage, error) {
	//	SELECT advisory_id,package_name,introduced,fixed,purl,cvssmetric2,cvssmetric3 FROM cve WHERE ecosystem = ? AND (
	//		package_name = ?
	//	OR package_name = ?
	//)

	rows, err := stmt.Query(ecosystem, osPackage.Name, osPackage.Source.SourceName)
	if err != nil {
		log.Printf("error querying database rows for package , %v", err)
		return VulnPackage{}, fmt.Errorf("error querying database rows for package , %v", err)
	}

	//loop through rows and check them for vulns
	//for now we assume only one will match so we return only one result

	var introduced, purl, packageName, cveID, cvssV2, cvssV3 string
	var isFixed sql.NullString
	for rows.Next() {
		if err := rows.Scan(
			&cveID,
			&packageName,
			&introduced,
			&isFixed,
			&purl,
			&cvssV2,
			&cvssV3); err != nil {

			log.Printf("failed scanning row data: %+v", err)
			return VulnPackage{}, fmt.Errorf("failed scanning row data: %w", err)
		}

		CvssMetricV2 := CvssV2Unmarshall(cvssV2)
		CvssMetricV3 := CvssV3Unmarshall(cvssV3)

		fixed := isFixed.String

		//if packageName == osPackage.sourceName name then we use the package version
		//this is a check to find out which version we use for checking for vulnerabilities
		if packageName == osPackage.Name && osPackage.Version != "" {
			result, err := CheckVulnerability(ecosystem, osPackage.Version, introduced, fixed)
			if err != nil {
				fmt.Printf("error somehow %v", err)
				return VulnPackage{}, err
			} else if result == Safe {
				//log.Printf("Safe Package %+v", osPackage)
				return VulnPackage{}, nil
			} //beyond this point thy package is vulnerable

			log.Printf("\nmatched Package name %v with upstream CVE:%v \nIntroduced:%v\nFixed:%v\n checking for vulnerablities..\n", cveID, packageName, introduced, fixed)
			pkg := VulnPackage{
				PackageName:  osPackage.Name,
				Installed:    osPackage.Version,
				Introduced:   introduced,
				Fixed:        fixed,
				CveId:        cveID,
				Purl:         purl,
				CvssMetricV2: CvssMetricV2,
				CvssMetricV3: CvssMetricV3,
			}

			return createVulnPackage(seen, result, pkg)
		} else
		//if the package name is equal to the source package name
		if packageName == osPackage.Source.SourceName && osPackage.Source.SourceVersion != "" {
			result, err := CheckVulnerability(ecosystem, osPackage.Source.SourceVersion, introduced, fixed)
			if err != nil {
				return VulnPackage{}, err
			} else if result == Safe {
				return VulnPackage{}, nil
			}

			//log.Printf("\nmatched Source name %v with upstream CVE:%v \nIntroduced:%v\nFixed:%v\n checking for vulnerablities..\n", cveID, packageName, introduced, fixed)

			pkg := VulnPackage{
				PackageName:  osPackage.Source.SourceName,
				Installed:    osPackage.Source.SourceVersion,
				Introduced:   introduced,
				Fixed:        fixed,
				CveId:        cveID,
				Purl:         purl,
				CvssMetricV2: CvssMetricV2,
				CvssMetricV3: CvssMetricV3,
			}
			return createVulnPackage(seen, result, pkg)
		}
	}

	if err = rows.Err(); err != nil {
		log.Printf("rows error, %v", err)
		return VulnPackage{}, err
	}

	return VulnPackage{}, nil //fmt.Errorf("unable to match the vulnerable packages for some unknown reason *sigh*\n")
}

func CvssV2Unmarshall(cvssV2 string) internals.CvssMetricV2 {
	var CvssMetricV2 internals.CvssMetricV2

	//in the Database we use NA for the values that do not exist
	if cvssV2 != "NA" {
		err := json.Unmarshal([]byte(cvssV2), &CvssMetricV2)
		if err != nil {
			log.Printf("error unmarshalling the data %+v \n %v", cvssV2, err)
		}
		return CvssMetricV2
	}
	return internals.CvssMetricV2{}
}

func CvssV3Unmarshall(cvssV3 string) internals.CvssMetricV30 {
	var CvssMetricV30 internals.CvssMetricV30

	if cvssV3 != "NA" {
		err := json.Unmarshal([]byte(cvssV3), &CvssMetricV30)
		if err != nil {
			log.Printf("error unmarshalling the data %+v \n %v", cvssV3, err)
		}
		return CvssMetricV30
	}
	return internals.CvssMetricV30{}
}

// createVulnPackage handles the results and uses the data provided
func createVulnPackage(seen map[string]bool, result Result, vulnPackage VulnPackage) (VulnPackage, error) {
	//check map
	//key = pkg.name+CVE-ID
	key := vulnPackage.PackageName + vulnPackage.CveId
	if _, ok := seen[key]; ok {
		return VulnPackage{}, fmt.Errorf("found duplicate CVE entry for the package:%v CVE-ID:%v", vulnPackage.PackageName, vulnPackage.CveId)
	} else {
		//add the entry to the map
		seen[key] = true
	}
	if result == Vulnerable {
		//package vulnerable
		return vulnPackage, nil
	}
	return VulnPackage{}, fmt.Errorf("HOW DID A VULN PACKAGE GET HERE!!?")
}
