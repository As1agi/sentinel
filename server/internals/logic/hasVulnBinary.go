package logic

import (
	"database/sql"
	"fmt"
	"log"
	"server/internals"
)

type VulnPackage struct {
	PackageName string `json:"package_name"`
	Installed   string `json:"installed"`
	Introduced  string `json:"introduced"`
	Fixed       string `json:"fixed"`
	Purl        string `json:"purl"`
	CveId       string `json:"CveId"`
	//CVV later on and maybe a summary from AI on how to fix?
}

var ()

//SELECT * FROM cves WHERE ecosystem = SBOM.ecosystem AND bin = SBOM.BIN[X].. then we get the version for the bin and do
//a comparison for the version... and if vulnerable we add to a list of vuln
//todo create another table in the DB linking vulnerable packages to a specific user, we will read from the table
// 	so we can send alerts to the web dashboard
// 	trigger a go routine as soon as we get an SBOM to check the user's current data for vulnerabilities?

// IsVulnerablePackage checks whether a package is vulnerable
// pass query as a parameter later for faster work

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
	SELECT advisory_id,package_name,introduced,fixed,purl FROM cve WHERE ecosystem = ? AND (
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
		//todo prepare statements for query for optimization
		rows, err := db.Query(queryGetOsPackages, sbomID, lastID)
		if err != nil {
			return []VulnPackage{}, fmt.Errorf("error fetching user os packages from database %v", err)
		}
		if err = rows.Err(); err != nil {
			return []VulnPackage{}, err
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
			if err != nil || vulnPkg.PackageName == "" {
				//log.Printf("Checked package %+v for vulnerabilities\n found:none\n Error:%v\n", pkg, err)
				continue
			}
			//log.Printf("Found vulnerabilities in package %+v\nFound:1\nVuln Pkg:%+v\n", pkg, vulnPkg)
			vulnPackages = append(vulnPackages, vulnPkg)
			vulnCount++
			//todo later on to prevent nuking our ram, we update the database in batches of 5 vulnPackages at a tim
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

	rows, err := stmt.Query(ecosystem, osPackage.Name, osPackage.Source.SourceName)
	if err != nil {
		return VulnPackage{}, fmt.Errorf("error querying database rows for package , %v", err)
	}
	if err = rows.Err(); err != nil {
		return VulnPackage{}, err
	}
	defer func() {
		_ = rows.Close()
	}()
	//loop through rows and check them for vulns
	//for now we assume only one will match so we return only one result

	var introduced, purl, packageName, cveID string
	var isFixed sql.NullString
	for rows.Next() {
		if err := rows.Scan(
			&cveID,
			&packageName,
			&introduced,
			&isFixed,
			&purl); err != nil {
			return VulnPackage{}, fmt.Errorf("failed scanning row data: %w", err)
		}

		//convert sql.NullString to string
		fixed := isFixed.String
		//todo use SQL later on to return source/original strings

		//if packageName == osPackage.sourceName name then we use the package version
		//this is a check to find out which version we use for checking for vulnerabilities
		if packageName == osPackage.Name && osPackage.Version != "" {
			result, err := CheckVulnerability(ecosystem, osPackage.Version, introduced, fixed)
			if err != nil {
				return VulnPackage{}, err
			} else if result == Safe {
				return VulnPackage{}, nil
			} //beyond this point thy package is vulnerable

			//log.Printf("\nmatched Package name %v with upstream CVE:%v \nIntroduced:%v\nFixed:%v\n checking for vulnerablities..\n", cveID, packageName, introduced, fixed)
			pkg := VulnPackage{
				PackageName: osPackage.Name,
				Installed:   osPackage.Version,
				Introduced:  introduced,
				Fixed:       fixed,
				CveId:       cveID,
				Purl:        purl,
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
			} //yeep it is vuln if it goes beyond this point
			//log.Printf("\nmatched Source name %v with upstream CVE:%v \nIntroduced:%v\nFixed:%v\n checking for vulnerablities..\n", cveID, packageName, introduced, fixed)
			//todo merge the two into one for cleaner code
			pkg := VulnPackage{
				PackageName: osPackage.Source.SourceName,
				Installed:   osPackage.Source.SourceVersion,
				Introduced:  introduced,
				Fixed:       fixed,
				CveId:       cveID,
				Purl:        purl,
			}
			return createVulnPackage(seen, result, pkg)
		}

		//error logging for when we cant match

		switch packageName {
		case osPackage.Name:
			return VulnPackage{}, nil
			//fmt.Errorf("package version not available , unable to match the data\n "+
			//",CVE package name:%v\n,OS package name:%v\nIntroduced:%v\nFixed:%v\n", osPackage.Name, packageName, introduced, fixed)

		case osPackage.Source.SourceName:
			//no version available for the source hence we cant do any comparison
			return VulnPackage{}, nil
			//fmt.Errorf("package version not available , unable to match the data\n "+
			//"CVE package name:%v\n,OS package name:%v\nIntroduced:%v\nFixed:%v\n", packageName, osPackage.Source.SourceName, introduced, fixed)

		}
		// if packageName == osPackage.Name {
		// 	return VulnPackage{}, nil
		// } else if packageName == osPackage.Source.SourceName {

		// 	return VulnPackage{}, nil
		// }
	}

	return VulnPackage{}, nil //fmt.Errorf("unable to match the vulnerable packages for some unknown reason *sigh*\n")
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
