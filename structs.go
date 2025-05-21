package main

// --- STRUCT DEFINITIONS ---

type ExploitedVulnerability struct {
	Aliases          string             `json:"aliases"`
	Assigner         string             `json:"assigner"`
	BaseScore        float64            `json:"baseScore"`
	BaseScoreVector  string             `json:"baseScoreVector"`
	BaseScoreVersion string             `json:"baseScoreVersion"`
	DatePublished    string             `json:"datePublished"`
	DateUpdated      string             `json:"dateUpdated"`
	Description      string             `json:"description"`
	EnisaIdProduct   []EnisaProductInfo `json:"enisaIdProduct"`
	EnisaIdVendor    []EnisaVendorInfo  `json:"enisaIdVendor"`
	Epss             float64            `json:"epss"`
	ExploitedSince   string             `json:"exploitedSince"`
	ID               string             `json:"id"`
	References       string             `json:"references"`
}

type CriticalVulnerability struct {
	Aliases          string             `json:"aliases"`
	Assigner         string             `json:"assigner"`
	BaseScore        float64            `json:"baseScore"`
	BaseScoreVector  string             `json:"baseScoreVector"`
	BaseScoreVersion string             `json:"baseScoreVersion"`
	DatePublished    string             `json:"datePublished"`
	DateUpdated      string             `json:"dateUpdated"`
	Description      string             `json:"description"`
	EnisaIdProduct   []EnisaProductInfo `json:"enisaIdProduct"`
	EnisaIdVendor    []EnisaVendorInfo  `json:"enisaIdVendor"`
	Epss             float64            `json:"epss"`
	ID               string             `json:"id"`
	References       string             `json:"references"`
}

type EnisaProductInfo struct {
	ID             string      `json:"id"`
	Product        ProductName `json:"product"`
	ProductVersion string      `json:"product_version"`
}

type ProductName struct {
	Name string `json:"name"`
}

type EnisaVendorInfo struct {
	ID     string     `json:"id"`
	Vendor VendorName `json:"vendor"`
}

type VendorName struct {
	Name string `json:"name"`
}

type VulnerabilityQueryResponse struct {
	Items []VulnerabilityItem `json:"items"`
	Total int                 `json:"total"`
}

type VulnerabilityItem struct {
	Aliases          string             `json:"aliases"`
	Assigner         string             `json:"assigner"`
	BaseScore        float64            `json:"baseScore"`
	BaseScoreVector  string             `json:"baseScoreVector"`
	BaseScoreVersion string             `json:"baseScoreVersion"`
	DatePublished    string             `json:"datePublished"`
	DateUpdated      string             `json:"dateUpdated"`
	Description      string             `json:"description"`
	EnisaIdProduct   []EnisaProductInfo `json:"enisaIdProduct"`
	EnisaIdVendor    []EnisaVendorInfo  `json:"enisaIdVendor"`
	Epss             float64            `json:"epss"`
	ID               string             `json:"id"`
	References       string             `json:"references"`
}

type VulnerabilityByID struct {
	Assigner              string             `json:"assigner"`
	BaseScore             float64            `json:"baseScore"`
	DatePublished         string             `json:"datePublished"`
	DateUpdated           string             `json:"dateUpdated"`
	Description           string             `json:"description"`
	EnisaID               string             `json:"enisa_id"`
	Epss                  float64            `json:"epss"`
	ID                    string             `json:"id"`
	References            string             `json:"references"`
	Status                string             `json:"status"`
	VulnerabilityAdvisory []interface{}      `json:"vulnerabilityAdvisory"` // Empty array in sample
	VulnerabilityProduct  []EnisaProductInfo `json:"vulnerabilityProduct"`
	VulnerabilityVendor   []EnisaVendorInfo  `json:"vulnerabilityVendor"`
}

type ENISAVulnerabilityByID struct {
	Aliases              string             `json:"aliases"`
	Assigner             string             `json:"assigner"`
	BaseScore            float64            `json:"baseScore"`
	DatePublished        string             `json:"datePublished"`
	DateUpdated          string             `json:"dateUpdated"`
	Description          string             `json:"description"`
	EnisaIdAdvisory      []interface{}      `json:"enisaIdAdvisory"`
	EnisaIdProduct       []EnisaProductInfo `json:"enisaIdProduct"`
	EnisaIdVendor        []EnisaVendorInfo  `json:"enisaIdVendor"`
	EnisaIdVulnerability []ENISAVulnWrapper `json:"enisaIdVulnerability"`
	Epss                 float64            `json:"epss"`
	ID                   string             `json:"id"`
	References           string             `json:"references"`
}

type ENISAVulnWrapper struct {
	ID            string            `json:"id"`
	Vulnerability VulnerabilityByID `json:"vulnerability"`
}
type AdvisoryByID struct {
	AdvisoryProduct   []EnisaProductInfo     `json:"advisoryProduct"`
	Aliases           string                 `json:"aliases"`
	BaseScore         float64                `json:"baseScore"`
	DatePublished     string                 `json:"datePublished"`
	DateUpdated       string                 `json:"dateUpdated"`
	Description       string                 `json:"description"`
	EnisaIdAdvisories []ENISAAdvisoryWrapper `json:"enisaIdAdvisories"`
}

type ENISAAdvisoryWrapper struct {
	ID      string             `json:"id"`
	EnisaId ENISAVulnerability `json:"enisaId"`
}

type ENISAVulnerability struct {
	Aliases          string            `json:"aliases"`
	Assigner         string            `json:"assigner"`
	BaseScore        float64           `json:"baseScore"`
	BaseScoreVector  string            `json:"baseScoreVector"`
	BaseScoreVersion string            `json:"baseScoreVersion"`
	DatePublished    string            `json:"datePublished"`
	DateUpdated      string            `json:"dateUpdated"`
	Description      string            `json:"description"`
	EnisaIdVendor    []EnisaVendorInfo `json:"enisaIdVendor"`
	Epss             float64           `json:"epss"`
	ID               string            `json:"id"`
	References       string            `json:"references"`
}

type LatestVulnerability struct {
	Aliases          string             `json:"aliases"`
	Assigner         string             `json:"assigner"`
	BaseScore        float64            `json:"baseScore"`
	BaseScoreVector  string             `json:"baseScoreVector"`
	BaseScoreVersion string             `json:"baseScoreVersion"`
	DatePublished    string             `json:"datePublished"`
	DateUpdated      string             `json:"dateUpdated"`
	Description      string             `json:"description"`
	EnisaIdProduct   []EnisaProductInfo `json:"enisaIdProduct"`
	EnisaIdVendor    []EnisaVendorInfo  `json:"enisaIdVendor"`
	Epss             float64            `json:"epss"`
	ID               string             `json:"id"`
	References       string             `json:"references"`
}

type LastVulnerability ExploitedVulnerability
