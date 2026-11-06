package saml

import (
	"encoding/xml"
	"strings"
	"testing"

	"gotest.tools/assert"
)

// A response that carries a Signature element and is too large for the
// signature library to detach must be refused with an error, not a panic.
// The check runs before any signature is verified, so anyone who can post to
// the ACS can send such a response.
func TestSPRefusesUndetachableSignedElementWithoutPanic(t *testing.T) {
	test := NewServiceProviderTest(t)
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	assert.NilError(t, xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata))

	resp := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/><samlp:Extensions>` +
		strings.Repeat("<p/>", 5000) + `</samlp:Extensions></samlp:Response>`

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ParseXMLResponse panicked: %v", r)
		}
	}()
	_, err := s.ParseXMLResponse([]byte(resp), nil, s.AcsURL)
	assert.Assert(t, err != nil)
}
