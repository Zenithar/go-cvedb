package nvd

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// Recent returns the latest recent CVEs.
func Recent() (d Data, hash string, err error) {
	return getData("https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz")
}

// Modified returns recently updated CVEs.
func Modified() (d Data, hash string, err error) {
	return getData("https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz")
}

// Year returns CVEs from the given year.
func Year(year uint64) (d Data, hash string, err error) {
	return getData(fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-%d.json.gz", year))
}

// -----------------------------------------------------------------------------

func getData(url string) (d Data, hash string, err error) {
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return
	}
	defer zr.Close()
	b, err := ioutil.ReadAll(zr)
	if err != nil {
		return
	}
	hash = fmt.Sprintf("%02X", sha256.Sum256(b))
	dec := json.NewDecoder(bytes.NewReader(b))
	err = dec.Decode(&d)
	return
}
