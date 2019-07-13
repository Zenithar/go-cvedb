/*
 * Copyright 2019 Thibault NORMAND
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

	// Un-gzip it
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return
	}
	defer zr.Close()

	// Read all in memory
	b, err := ioutil.ReadAll(zr)
	if err != nil {
		return
	}

	// Calculate fingerprint
	hash = fmt.Sprintf("%02X", sha256.Sum256(b))

	// Decode json
	dec := json.NewDecoder(bytes.NewReader(b))
	err = dec.Decode(&d)

	return
}
