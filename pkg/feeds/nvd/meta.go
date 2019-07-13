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
	"bufio"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Meta contains information about the last update to the NVD.
type Meta struct {
	LastModifiedDate time.Time `json:"lastModifiedDate"`
	Size             int64     `json:"size"`
	ZipSize          int64     `json:"zipSize"`
	GZSize           int64     `json:"gzSize"`
	SHA256           string    `json:"sha256"`
}

// RecentMetadataURL is the URL where metadata about recent CVE data is located.
const RecentMetadataURL = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.meta"

// RecentMetadata returns metadata about the current version of the "recent" file.
func RecentMetadata() (m Meta, err error) {
	return getMetadata(RecentMetadataURL)
}

// ModifiedMetadataURL is the URL where metadata about recently modified CVE data is located.
const ModifiedMetadataURL = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.meta"

// ModifiedMetadata returns metadata about the current version of the "modified" file.
func ModifiedMetadata() (m Meta, err error) {
	return getMetadata(ModifiedMetadataURL)
}

// YearMetadata returns metadata for the given year.
func YearMetadata(year uint64) (m Meta, err error) {
	return getMetadata(fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-%d.meta", year))
}

// -----------------------------------------------------------------------------

func getMetadata(url string) (m Meta, err error) {
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		firstColon := strings.Index(line, ":")
		if firstColon == -1 {
			continue
		}
		prefix := string([]rune(line)[:firstColon])
		suffix := string([]rune(line)[firstColon+1:])
		switch prefix {
		case "lastModifiedDate":
			if m.LastModifiedDate, err = time.Parse(time.RFC3339, suffix); err != nil {
				err = fmt.Errorf("could not parse '%v' as time: %v", suffix, err)
				return
			}
		case "size":
			if m.Size, err = strconv.ParseInt(suffix, 10, 64); err != nil {
				err = fmt.Errorf("could not parse size '%v' as int64: %v", suffix, err)
				return
			}
		case "zipSize":
			if m.ZipSize, err = strconv.ParseInt(suffix, 10, 64); err != nil {
				err = fmt.Errorf("could not parse zipSize '%v' as int64: %v", suffix, err)
				return
			}
		case "gzSize":
			if m.GZSize, err = strconv.ParseInt(suffix, 10, 64); err != nil {
				err = fmt.Errorf("could not parse gzSize '%v' as int64: %v", suffix, err)
				return
			}
		case "sha256":
			m.SHA256 = suffix
		}
	}
	if sErr := scanner.Err(); sErr != nil {
		err = sErr
		return
	}
	return
}
