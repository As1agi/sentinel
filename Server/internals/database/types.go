package database

// SBOM
// the shape of the SBOM we get from the user
// source Casandra\ User\ Agent/ internals/sbom/types.go
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

type OSPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	Source  Src    `json:"source"`
}

type Src struct {
	SourceName    string `json:"source_name"`
	SourceVersion string `json:"source_version"`
}

type CleanVulnerability struct {
	AdvisoryID  string   `json:"advisory_id"`
	Upstream    []string `json:"upstream,omitempty"`
	Ecosystem   string   `json:"ecosystem"`
	PackageName string   `json:"package_name"`
	Purl        string   `json:"purl,omitempty"`
	Introduced  string   `json:"introduced"`
	Fixed       string   `json:"fixed"`
}
