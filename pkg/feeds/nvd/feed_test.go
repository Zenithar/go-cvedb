package nvd_test

import (
	"testing"

	"go.zenithar.org/cvedb/pkg/feeds/nvd"

	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

func TestRecent(t *testing.T) {
	defer gock.Off()

	// Mock request
	gock.New("https://nvd.nist.gov").
		Get("feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz").
		Reply(200).
		File("./fixtures/nvdcve-1.0-recent.json.gz")

	data, h, err := nvd.Recent()
	assert.NoError(t, err, "Error should not be raised")
	assert.NotNil(t, data, "Data should not be nil")
	assert.NotEmpty(t, h, "Hash should not be nil")

	// Check data
	assert.Equal(t, "20945F14B67740DF80575D5747593234F63F9349AAFC58A8BEDE3CFCEFA8A8A9", h, "Hash should be as expected")
	assert.Equal(t, 4, len(data.CVEItems), "CVE Bundle should contains expected CVE count")
}

func TestModified(t *testing.T) {
	defer gock.Off()

	// Mock request
	gock.New("https://nvd.nist.gov").
		Get("feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz").
		Reply(200).
		File("./fixtures/nvdcve-1.0-modified.json.gz")

	data, h, err := nvd.Modified()
	assert.NoError(t, err, "Error should not be raised")
	assert.NotNil(t, data, "Data should not be nil")
	assert.NotEmpty(t, h, "Hash should not be nil")

	// Check data
	assert.Equal(t, "A4BFED93CFC017266D49E5D2175CA899C01EEBECD99CB7FD122F06F465A2CDD4", h, "Hash should be as expected")
}

func TestYear(t *testing.T) {
	defer gock.Off()

	// Mock request
	gock.New("https://nvd.nist.gov").
		Get("feeds/json/cve/1.0/nvdcve-1.0-2019.json.gz").
		Reply(200).
		File("./fixtures/nvdcve-1.0-modified.json.gz")

	data, h, err := nvd.Year(2019)
	assert.NoError(t, err, "Error should not be raised")
	assert.NotNil(t, data, "Data should not be nil")
	assert.NotEmpty(t, h, "Hash should not be nil")

	// Check data
	assert.Equal(t, "A4BFED93CFC017266D49E5D2175CA899C01EEBECD99CB7FD122F06F465A2CDD4", h, "Hash should be as expected")
}
