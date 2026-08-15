package datasets

import "server/internals"

type NvdAdvisory struct {
	ID string `json:"id"`
	//VulnStatus   string         `json:"vulnStatus,omitempty"`
	CveTags      []any                    `json:"cveTags,omitempty"`
	Descriptions []internals.Descriptions `json:"descriptions,omitempty"`
	Affected     []Affected               `json:"affected,omitempty"`
	Metrics      Metrics                  `json:"metrics,omitempty"`
	//References     []References     `json:"references,omitempty"`
}

type Descriptions struct {
	Lang  string `json:"lang,omitempty"`
	Value string `json:"value,omitempty"`
}
type Versions struct {
	Version string `json:"version,omitempty"`
	Status  string `json:"status,omitempty"`
}
type AffectedData struct {
	Vendor   string     `json:"vendor,omitempty"`
	Product  string     `json:"product,omitempty"`
	Versions []Versions `json:"versions,omitempty"`
}
type Affected struct {
	Source       string         `json:"source,omitempty"`
	AffectedData []AffectedData `json:"affectedData,omitempty"`
}

type Metrics struct {
	CvssMetricV30 []internals.CvssMetricV30 `json:"cvssMetricV30,omitempty"`
	CvssMetricV2  []internals.CvssMetricV2  `json:"cvssMetricV2,omitempty"`
}
type Description struct {
	Lang  string `json:"lang,omitempty"`
	Value string `json:"value,omitempty"`
}
type Weaknesses struct {
	Source      string        `json:"source,omitempty"`
	Type        string        `json:"type,omitempty"`
	Description []Description `json:"description,omitempty"`
}
type CpeMatch struct {
	Vulnerable            bool   `json:"vulnerable,omitempty"`
	Criteria              string `json:"criteria,omitempty"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	MatchCriteriaID       string `json:"matchCriteriaId,omitempty"`
}
type Nodes struct {
	Operator string     `json:"operator,omitempty"`
	Negate   bool       `json:"negate,omitempty"`
	CpeMatch []CpeMatch `json:"cpeMatch,omitempty"`
}
type Configurations struct {
	Nodes []Nodes `json:"nodes,omitempty"`
}
type References struct {
	URL    string   `json:"url,omitempty"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}
