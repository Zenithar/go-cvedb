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

package models

import (
	"time"
)

// Advisory is the advisory information holder
type Advisory struct {
	ID               string            `json:"id" bson:"_id"`
	Description      map[string]string `json:"description" bson:"description"`
	Score            float64           `json:"score" bson:"score"`
	LastModifiedDate time.Time         `json:"lastModifiedDate" bson:"lastModifiedDate"`
	PublishedDate    time.Time         `json:"publishedDate" bson:"publishedDate"`
	Cve              string            `json:"cve" bson:"cve"`
	CVSS             Cvss              `json:"cvss" bson:"cvss"`
	Cwe              []string          `json:"cwe" bson:"cwe"`
	References       []Reference       `json:"refs" bson:"refs"`
	Affects          []Affect          `json:"affects" bson:"affects"`
}

// -----------------------------------------------------------------------------

// Validate entity constraints
func (a *Advisory) Validate() error {
	return nil
}
