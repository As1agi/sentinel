package internals

const (
	cveSavePath = "../cve.json"
)

// VulnPackage is a struct with info about a vuln package which we display to the user
type VulnPackage struct {
	PackageName string `json:"package_name"`
	Introduced  string `json:"introduced"`
	Fixed       string `json:"fixed"`
	Purl        string `json:"purl"`
	//CVV later on and maybe a summary from AI on how to fix?
}

// SBOM
// the shape of the SBOM we get from the user
type SBOM struct {
	Timestamp     string      `json:"timestamp"`
	OS            string      `json:"os"`
	OSVersion     string      `json:"os_version"`
	OSEcosystem   string      `json:"OSEcosystem"`
	KernelVersion string      `json:"kernel_version"`
	Architecture  string      `json:"architecture"`
	Hostname      string      `json:"hostname"`
	Packages      []OSPackage `json:"packages"`
	MachineID     string      `json:"machineID"`
}

// OSPackage is the structure for a single entry in the SBOM from the kernel
type OSPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	Source  Src    `json:"source"`
}

// Src is the structure for the source information of a package in the SBOM
// can be nil if no source is available
type Src struct {
	SourceName    string `json:"source_name"`
	SourceVersion string `json:"source_version"`
}

// CleanVulnerability is the final structure for the CVE data which is stored in the database
type CleanVulnerability struct {
	AdvisoryID string `json:"advisory_id"`
	//AffectedVersion []string `json:"affectedVersion"`
	//EcosystemSpecific EcosystemSpecificBinaries `json:"ecosystem_specific"`
	Upstream []string `json:"upstream,omitempty"`
	//CVEIDs      []string `json:"cve_ids,omitempty"`
	Ecosystem   string `json:"ecosystem"`
	PackageName string `json:"package_name"`
	Purl        string `json:"purl,omitempty"`
	Introduced  string `json:"introduced"`
	Fixed       string `json:"fixed"`
}
