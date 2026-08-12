package datasets

// Upstream OSV structural definitions (only matching the fields we want to extract)
type OsvAdvisory struct {
	ID       string        `json:"id"`
	Upstream []string      `json:"upstream,omitempty"`
	Aliases  []string      `json:"aliases,omitempty"`
	Affected []OsvAffected `json:"affected,omitempty"`
}

type OsvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		Purl      string `json:"purl,omitempty"`
	} `json:"package"`
	Ranges []struct {
		Type   string     `json:"type"`
		Events []OsvEvent `json:"events"`
	} `json:"ranges"`
	//Versions []string `json:"versions"` todo uncomment for data enrichment later on
	//EcosystemSpecific EcosystemSpecificBinaries `json:"ecosystem_specific"`
}

type OsvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type EcosystemSpecificBinaries struct {
	Binaries []Binary `json:"binaries"`
}
type Binary struct {
	BinaryName    string `json:"binary_name"`
	BinaryVersion string `json:"binary_version"`
}
