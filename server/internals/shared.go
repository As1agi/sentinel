package internals

// ========================================================================================

// NormalizedVuln is the final structure for the CVE data which is stored in the database
type NormalizedVuln struct {
	AdvisoryID   string          `json:"advisory_id"`
	Upstream     []string        `json:"upstream,omitempty"`
	Ecosystem    string          `json:"ecosystem,omitempty"`
	PackageName  string          `json:"package_name,omitempty"`
	Purl         string          `json:"purl,omitempty"`
	Cpe          string          `json:"cpe,omitempty"`
	Description  []Descriptions  `json:"description,omitempty"`
	CvssMetricV2 []CvssMetricV2  `json:"cvssMetricV2,omitempty"`
	CvssMetricV3 []CvssMetricV30 `json:"cvssMetricV3,omitempty"`
	Introduced   string          `json:"introduced,omitempty"`
	Fixed        string          `json:"fixed,omitempty"`
}

type Descriptions struct {
	Lang  string `json:"lang,omitempty"`
	Value string `json:"value,omitempty"`
}

type CvssMetricV30 struct {
	//extract only the nvd.org data initially
	Source              string   `json:"source,omitempty"`
	Type                string   `json:"type,omitempty"`
	CvssData            CvssData `json:"cvssData,omitempty"`
	ExploitabilityScore float64  `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64  `json:"impactScore,omitempty"`
}

type CvssData struct {
	Version               string  `json:"version,omitempty"`
	VectorString          string  `json:"vectorString,omitempty"`
	BaseScore             float64 `json:"baseScore,omitempty"`
	BaseSeverity          string  `json:"baseSeverity,omitempty"`
	AttackVector          string  `json:"attackVector,omitempty"`
	AttackComplexity      string  `json:"attackComplexity,omitempty"`
	PrivilegesRequired    string  `json:"privilegesRequired,omitempty"`
	UserInteraction       string  `json:"userInteraction,omitempty"`
	Scope                 string  `json:"scope,omitempty"`
	ConfidentialityImpact string  `json:"confidentialityImpact,omitempty"`
	IntegrityImpact       string  `json:"integrityImpact,omitempty"`
	AvailabilityImpact    string  `json:"availabilityImpact,omitempty"`
}
type CvssMetricV2 struct {
	Source                  string   `json:"source,omitempty"`
	Type                    string   `json:"type,omitempty"`
	CvssData                CvssData `json:"cvssData,omitempty"`
	BaseSeverity            string   `json:"baseSeverity,omitempty"`
	ExploitabilityScore     float64  `json:"exploitabilityScore,omitempty"`
	ImpactScore             float64  `json:"impactScore,omitempty"`
	AcInsufInfo             bool     `json:"acInsufInfo,omitempty"`
	ObtainAllPrivilege      bool     `json:"obtainAllPrivilege,omitempty"`
	ObtainUserPrivilege     bool     `json:"obtainUserPrivilege,omitempty"`
	ObtainOtherPrivilege    bool     `json:"obtainOtherPrivilege,omitempty"`
	UserInteractionRequired bool     `json:"userInteractionRequired,omitempty"`
}

// ================================================================================================

// VulnPackage is a struct with info about a vuln package which we display to the user
type VulnPackage struct {
	PackageName string `json:"package_name"`
	Installed   string `json:"installed"`
	Introduced  string `json:"introduced"`
	Fixed       string `json:"fixed"`
	Purl        string `json:"purl"`
	CveId       string `json:"CveId"`
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
