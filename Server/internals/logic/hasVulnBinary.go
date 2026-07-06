package logic

import (
	"database/sql"
	"fmt"
	"log"
	"server/internals"
)

type VulnPackage struct {
	PackageName string `json:"package_name"`
	Introduced  string `json:"introduced"`
	Fixed       string `json:"fixed"`
	Purl        string `json:"purl"`
	//CVV later on and maybe a summary from AI on how to fix?
}

var (
	queryGetMatchingCVEs = `
	SELECT package_name,introduced,fixed,purl FROM cve WHERE ecosystem = ? AND (
	    package_name = ? 
	    OR package_name = ?
	)
`
)

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
	var emptyVuln VulnPackage

	//we need to get X rows of osPackages and create them in a struct the pass them one by one to is vuln package
	//then we create a batch of data 5 vulns to create a transaction then we commit them to another table in the database
	//then the user can just get data from that table for vuln packages

	QuerygetUserId := `
	SELECT id from users where hostname = ?
`
	QUerygetSbomId := `
	SELECT id,os_ecosystem FROM sboms WHERE (user_id = ? AND machine_id = ?)
`
	QuerygetOsPackages := `
	SELECT id,name,version,source_name,source_version FROM packages WHERE sbom_id = ? AND id > ? ORDER BY id LIMIT 25
`

	//prepare the statement for querying the cve table for matching CVE packages
	getMatchingCVEStmt, err := db.Prepare(queryGetMatchingCVEs)
	if err != nil {
		return nil, fmt.Errorf("error preparing statement for fetching matching CVEs , %v\n", err)
	}
	defer getMatchingCVEStmt.Close()

	var userID int64
	//fist get the userId
	row := db.QueryRow(QuerygetUserId, hostName)
	err = row.Scan(&userID)
	if err != nil {
		return []VulnPackage{}, fmt.Errorf("error fetching user ID from database %v\n", err)
	}

	//then we get the SBOM id for the machine
	var sbomID int64
	var ecosystem string
	row = db.QueryRow(QUerygetSbomId, userID, machineID)
	err = row.Scan(&sbomID, &ecosystem)
	if err != nil {
		return []VulnPackage{}, fmt.Errorf("error fetching user sbomID from database %v\n", err)
	}

	//then we use the SBOM ID to get the packages for the SBOM from the database, marshal them into structs
	//then we perfom ops on them

	//lastID is used to track the last ID for the previous query
	var lastID = 0
	var vulnCount = 0
	for {

		var count = 0
		rows, err := db.Query(QuerygetOsPackages, sbomID, lastID)
		if err != nil {
			return []VulnPackage{}, fmt.Errorf("error fetching user os packages from database %v\n", err)
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
				return nil, fmt.Errorf("error scanning rows for SBOM for User: %v\n machineID: %v\n  last ID: %v\n", hostName, machineID, lastID)
			}

			lastID = id
			count++
			// audit package
			vulnPkg, err := IsVulnerablePackage(getMatchingCVEStmt, ecosystem, pkg)
			if err != nil || vulnPkg == emptyVuln {
				log.Printf("Checking package %+v for vulnerabilities\n found:none\n Error:%v\n", pkg, err)
				continue
			}
			log.Printf("Checking package %+v for vulnerabilities\nFound:1\nVuln Pkg:%+v\n", pkg, vulnPkg)
			vulnPackages = append(vulnPackages, vulnPkg)
			vulnCount++
			//todo later on to prevent nuking our ram, we update the database in batches of 5 vulnPackages at a tim
		}
		if count == 0 {
			break
		}
		rows.Close()
	}
	log.Printf("Found %v vuln packages for the User:%v , machineID:%v\n last ID: %v\n", vulnCount, hostName, machineID, lastID)
	return vulnPackages, nil
}

func IsVulnerablePackage(stmt *sql.Stmt, ecosystem string, osPackage internals.OSPackage) (VulnPackage, error) {

	//query the database for the data
	rows, err := stmt.Query(ecosystem, osPackage.Name, osPackage.Source.SourceName)
	if err != nil {
		return VulnPackage{}, fmt.Errorf("error querying database rows for package , %v\n", err)
	}

	defer rows.Close()
	//loop through rows and check them for vulns
	//for now we assume only one will match so we return only one result
	for rows.Next() {
		var introduced, purl, packageName string
		var isFixed sql.NullString // Protects against unpatched/NULL database fields

		if err := rows.Scan(&packageName, &introduced, &isFixed, &purl); err != nil {
			return VulnPackage{}, fmt.Errorf("failed scanning row data: %w", err)
		}

		//convert sql.NullString to string
		fixed := isFixed.String
		//todo use SQL later on to return source/original strings
		
		//if packageName == osPackage.sourceName name then we use the package version
		//this is a check to find out which version we use for checking for vulnerabilities
		if packageName == osPackage.Name && osPackage.Version != "" {
			result := CheckVulnerability(ecosystem, osPackage.Version, introduced, fixed)
			//todo merge the two into one for cleaner code
			return createVulnPackage(result, osPackage.Name, introduced, fixed, purl)
		} else if packageName == osPackage.Name && osPackage.Version == "" {
			return VulnPackage{}, fmt.Errorf("package version not available , unable to match the data\n "+
				",CVE package name:%v\n,OS package name:%v\nIntroduced:%v\nFixed:%v\n", osPackage.Name, packageName, introduced, fixed)
		}

		//if packageName == osPackage.package name then we use the normal package version
		if packageName == osPackage.Source.SourceName && osPackage.Source.SourceVersion != "" {
			result := CheckVulnerability(ecosystem, osPackage.Source.SourceVersion, introduced, fixed)
			//todo merge the two into one for cleaner code
			return createVulnPackage(result, osPackage.Source.SourceName, introduced, fixed, purl)
		} else if packageName == osPackage.Source.SourceName && osPackage.Source.SourceVersion == "" {
			//no version available for the source hence we cant do any comparison
			return VulnPackage{}, fmt.Errorf("package version not available , unable to match the data\n "+
				",CVE package name:%v\n,OS package name:%v\nIntroduced:%v\nFixed:%v\n", packageName, osPackage.Source.SourceName, introduced, fixed)
		}
	}

	return VulnPackage{}, fmt.Errorf("unable to match the vulnerable packages for some unknown reason *sigh*\n")
}

// createVulnPackage handles the results and uses the data provided
func createVulnPackage(result Result, packageName string, introduced string, fixed string, purl string) (VulnPackage, error) {
	if result == -1 {
		//invalid version
		return VulnPackage{}, nil
	} else if result == 1 {
		//package vulnerable
		return VulnPackage{
			PackageName: packageName,
			Purl:        purl,
			Introduced:  introduced,
			Fixed:       fixed,
		}, nil
	} else if result == 0 {
		return VulnPackage{}, nil
	}
	return VulnPackage{}, fmt.Errorf("invalid results\n")
}
