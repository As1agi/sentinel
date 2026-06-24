package server

type SBOM struct {
	Timestamp     string      `json:"timestamp"`
	OS            string      `json:"os"`
	OSVersion     string      `json:"os_version"`
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
