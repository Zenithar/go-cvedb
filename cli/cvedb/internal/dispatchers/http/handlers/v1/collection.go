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

package v1

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"go.zenithar.org/pkg/web/respond"
)

var jsonpbMarshaler = &jsonpb.Marshaler{OrigName: true}

// CollectionResponse is used to serialize protobuf as valid json.
type CollectionResponse struct {
	*respond.Resource
	Members interface{} `json:"members"`
}

// Cursor is the cursor paginator.
type Cursor struct {
	Next     string `json:"next"`
	Previous string `json:"prev"`
}

// -----------------------------------------------------------------------------

var protoMessageType = reflect.TypeOf((*proto.Message)(nil)).Elem()

// MarshalJSON is used to export resource as a JSON encoded payload
func (j CollectionResponse) MarshalJSON() ([]byte, error) {
	// Preconditions
	v := reflect.ValueOf(j.Members)
	if v.Kind() != reflect.Slice {
		return nil, fmt.Errorf("Members must be a slice")
	}

	out := fmt.Sprintf(`{"@context":"%s","@id":"%s","@type":"%s"`, j.Context, j.ID, j.Type)

	var members string

	collectionType := reflect.ValueOf(j.Members)
	result := reflect.New(reflect.TypeOf(j.Members).Elem())

	if result.Elem().Type().AssignableTo(protoMessageType) {
		var messages []string
		for i := 0; i < collectionType.Len(); i++ {
			memberBody, err := jsonpbMarshaler.MarshalToString(collectionType.Index(i).Interface().(proto.Message))
			if err != nil {
				return nil, errors.Wrap(err, "Unable to marshal protobuf collection")
			}
			messages = append(messages, memberBody)
		}

		members = fmt.Sprintf(`[%s]`, strings.Join(messages, ","))
	} else {
		body, err := json.Marshal(j.Members)
		if err != nil {
			return nil, errors.Wrap(err, "Unable to marshal generic collection")
		}
		members = string(body)
	}

	out = fmt.Sprintf(`%s, "members":%s}`, out, members)

	return []byte(out), nil
}
