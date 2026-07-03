package dataset

// Upstream OSV structural definitions (only matching the fields we want to extract)
type OSVAdvisory struct {
	ID       string        `json:"id"`
	Upstream []string      `json:"upstream,omitempty"`
	Aliases  []string      `json:"aliases,omitempty"`
	Affected []OSVAffected `json:"affected,omitempty"`
}

type OSVAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		Purl      string `json:"purl,omitempty"`
	} `json:"package"`
	Ranges []struct {
		Type   string     `json:"type"`
		Events []OSVEvent `json:"events"`
	} `json:"ranges"`
	//Versions []string `json:"versions"` todo uncomment for data enrichment later on
	//EcosystemSpecific EcosystemSpecificBinaries `json:"ecosystem_specific"`
}

type OSVEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// memory-efficient, flattened output structure

type EcosystemSpecificBinaries struct {
	Binaries []Binary `json:"binaries"`
}
type Binary struct {
	BinaryName    string `json:"binary_name"`
	BinaryVersion string `json:"binary_version"`
}
