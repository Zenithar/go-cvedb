package nvd_test

import (
	"testing"

	"go.zenithar.org/cvedb/pkg/feeds/nvd"

	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

func TestRecentMetadata(t *testing.T) {
	defer gock.Off()

	// Mock request
	gock.New("https://nvd.nist.gov").
		Get("/feeds/json/cve/1.0/nvdcve-1.0-recent.meta").
		Reply(200).
		File("./fixtures/nvdcve-1.0-recent.meta")

	// Do the query
	m, err := nvd.RecentMetadata()
	assert.NoError(t, err, "Error should not be raised")
	assert.NotNil(t, m, "Meta should not be nil")

	// Check results
	assert.Equal(t, int64(29154121), m.Size, "Size is not has expected")
	assert.Equal(t, int64(928661), m.ZipSize, "ZipSize is not has expected")
	assert.Equal(t, int64(928521), m.GZSize, "GZSize is not has expected")
	assert.Equal(t, "819AB53441E673809ECB5CA64EB32F6F604614CF99C7F88F29ADA33B711DC1A5", m.SHA256, "SHA256 is not has expected")
}

func TestModifiedMetadata(t *testing.T) {
	defer gock.Off()

	// Mock request
	gock.New("https://nvd.nist.gov").
		Get("/feeds/json/cve/1.0/nvdcve-1.0-modified.meta").
		Reply(200).
		File("./fixtures/nvdcve-1.0-modified.meta")

	// Do the query
	m, err := nvd.ModifiedMetadata()
	assert.NoError(t, err, "Error should not be raised")
	assert.NotNil(t, m, "Meta should not be nil")

	// Check results
	assert.Equal(t, int64(30967907), m.Size, "Size is not has expected")
	assert.Equal(t, int64(1011487), m.ZipSize, "ZipSize is not has expected")
	assert.Equal(t, int64(1011343), m.GZSize, "GZSize is not has expected")
	assert.Equal(t, "344867EAB1BDD1DB8EA555DBE62D0DB56AB74F7D2606CF51B91FB900F97AB5D7", m.SHA256, "SHA256 is not has expected")
}

func TestYearMetadata(t *testing.T) {
	defer gock.Off()

	// Mock request
	gock.New("https://nvd.nist.gov").
		Get("/feeds/json/cve/1.0/nvdcve-1.0-2019.meta").
		Reply(200).
		File("./fixtures/nvdcve-1.0-modified.meta")

	// Do the query
	m, err := nvd.YearMetadata(2019)
	assert.NoError(t, err, "Error should not be raised")
	assert.NotNil(t, m, "Meta should not be nil")

	// Check results
	assert.Equal(t, int64(30967907), m.Size, "Size is not has expected")
	assert.Equal(t, int64(1011487), m.ZipSize, "ZipSize is not has expected")
	assert.Equal(t, int64(1011343), m.GZSize, "GZSize is not has expected")
	assert.Equal(t, "344867EAB1BDD1DB8EA555DBE62D0DB56AB74F7D2606CF51B91FB900F97AB5D7", m.SHA256, "SHA256 is not has expected")
}
