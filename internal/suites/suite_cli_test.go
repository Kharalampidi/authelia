package suites

import (
	"regexp"
	"strings"
	"testing"

	"github.com/matryer/is"
	"github.com/poy/onpar"
)

func TestCLISuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping suite test in short mode")
	}

	o := onpar.New()
	defer o.Run(t)

	o.BeforeEach(func(t *testing.T) (*testing.T, *CommandSuite) {
		s := setupCLITest()
		return t, s
	})

	o.Spec("TestShouldPrintBuildInformation", func(t *testing.T, s *CommandSuite) {
		is := is.New(t)
		output, err := s.Exec("authelia-backend", []string{"authelia", s.testArg, s.coverageArg, "build-info"})
		is.NoErr(err)
		is.True(strings.Contains(output, "Last Tag: "))
		is.True(strings.Contains(output, "State: "))
		is.True(strings.Contains(output, "Branch: "))
		is.True(strings.Contains(output, "Build Number: "))
		is.True(strings.Contains(output, "Build OS: "))
		is.True(strings.Contains(output, "Build Arch: "))
		is.True(strings.Contains(output, "Build Date: "))

		r := regexp.MustCompile(`^Last Tag: (v\d+\.\d+\.\d+|unknown)\nState: (tagged|untagged) (clean|dirty)\nBranch: [^\s\n]+\nCommit: ([0-9a-f]{40}|unknown)\nBuild Number: \d+\nBuild OS: (linux|darwin|windows|freebsd)\nBuild Arch: (amd64|arm|arm64)\nBuild Date: ((Sun|Mon|Tue|Wed|Thu|Fri|Sat), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} [+-]\d{4})?\nExtra: \n`)
		is.True(r.MatchString(output))
	})

	o.Spec("TestShouldPrintVersion", func(t *testing.T, s *CommandSuite) {
		is := is.New(t)
		output, err := s.Exec("authelia-backend", []string{"authelia", s.testArg, s.coverageArg, "--version"})
		is.NoErr(err)
		is.True(strings.Contains(output, "authelia version"))
	})

	o.Spec("TestShouldValidateConfig", func(t *testing.T, s *CommandSuite) {
		is := is.New(t)
		output, err := s.Exec("authelia-backend", []string{"authelia", s.testArg, s.coverageArg, "validate-config", "/config/configuration.yml"})
		is.NoErr(err)
		is.True(strings.Contains(output, "Configuration parsed successfully without errors"))
	})

	o.Spec("TestShouldFailValidateConfig", func(t *testing.T, s *CommandSuite) {
		is := is.New(t)
		output, err := s.Exec("authelia-backend", []string{"authelia", s.testArg, s.coverageArg, "validate-config", "/config/invalid.yml"})
		is.True(err != nil)
		is.True(strings.Contains(output, "Error Loading Configuration: stat /config/invalid.yml: no such file or directory"))
	})

	o.Spec("TestShouldHashPasswordArgon2id", func(t *testing.T, s *CommandSuite) {
		is := is.New(t)
		output, err := s.Exec("authelia-backend", []string{"authelia", s.testArg, s.coverageArg, "hash-password", "test", "-m", "32", "-s", "test1234"})
		is.NoErr(err)
		is.True(strings.Contains(output, "Password hash: $argon2id$v=19$m=32768,t=1,p=8"))
	})

	o.Spec("TestShouldHashPasswordSHA512", func(t *testing.T, s *CommandSuite) {
		is := is.New(t)
		output, err := s.Exec("authelia-backend", []string{"authelia", s.testArg, s.coverageArg, "hash-password", "test", "-z"})
		is.NoErr(err)
		is.True(strings.Contains(output, "Password hash: $6$rounds=50000"))
	})

	o.Spec("TestShouldGenerateCertificateRSA", func(t *testing.T, s *CommandSuite) {
		is := is.New(t)
		output, err := s.Exec("authelia-backend", []string{"authelia", s.testArg, s.coverageArg, "certificates", "generate", "--host", "*.example.com", "--dir", "/tmp/"})
		is.NoErr(err)
		is.True(strings.Contains(output, "Certificate Public Key written to /tmp/cert.pem"))
		is.True(strings.Contains(output, "Certificate Private Key written to /tmp/key.pem"))
	})

	o.Spec("TestShouldGenerateCertificateRSAWithIPAddress", func(t *testing.T, s *CommandSuite) {
		is := is.New(t)
		output, err := s.Exec("authelia-backend", []string{"authelia", s.testArg, s.coverageArg, "certificates", "generate", "--host", "127.0.0.1", "--dir", "/tmp/"})
		is.NoErr(err)
		is.True(strings.Contains(output, "Certificate Public Key written to /tmp/cert.pem"))
		is.True(strings.Contains(output, "Certificate Private Key written to /tmp/key.pem"))
	})

	o.Spec("TestShouldGenerateCertificateRSAWithStartDate", func(t *testing.T, s *CommandSuite) {
		is := is.New(t)
		output, err := s.Exec("authelia-backend", []string{"authelia", s.testArg, s.coverageArg, "certificates", "generate", "--host", "*.example.com", "--dir", "/tmp/", "--start-date", "'Jan 1 15:04:05 2011'"})
		is.NoErr(err)
		is.True(strings.Contains(output, "Certificate Public Key written to /tmp/cert.pem"))
		is.True(strings.Contains(output, "Certificate Private Key written to /tmp/key.pem"))
	})

	o.Spec("TestShouldFailGenerateCertificateRSAWithStartDate", func(t *testing.T, s *CommandSuite) {
		is := is.New(t)
		output, err := s.Exec("authelia-backend", []string{"authelia", s.testArg, s.coverageArg, "certificates", "generate", "--host", "*.example.com", "--dir", "/tmp/", "--start-date", "Jan"})
		is.True(err != nil)
		is.True(strings.Contains(output, "Failed to parse start date: parsing time \"Jan\" as \"Jan 2 15:04:05 2006\": cannot parse \"\" as \"2\""))
	})

	o.Spec("TestShouldGenerateCertificateCA", func(t *testing.T, s *CommandSuite) {
		is := is.New(t)
		output, err := s.Exec("authelia-backend", []string{"authelia", s.testArg, s.coverageArg, "certificates", "generate", "--host", "*.example.com", "--dir", "/tmp/", "--ca"})
		is.NoErr(err)
		is.True(strings.Contains(output, "Certificate Public Key written to /tmp/cert.pem"))
		is.True(strings.Contains(output, "Certificate Private Key written to /tmp/key.pem"))
	})

	o.Spec("TestShouldGenerateCertificateEd25519", func(t *testing.T, s *CommandSuite) {
		is := is.New(t)
		output, err := s.Exec("authelia-backend", []string{"authelia", s.testArg, s.coverageArg, "certificates", "generate", "--host", "*.example.com", "--dir", "/tmp/", "--ed25519"})
		is.NoErr(err)
		is.True(strings.Contains(output, "Certificate Public Key written to /tmp/cert.pem"))
		is.True(strings.Contains(output, "Certificate Private Key written to /tmp/key.pem"))
	})

	o.Spec("TestShouldFailGenerateCertificateECDSA", func(t *testing.T, s *CommandSuite) {
		is := is.New(t)
		output, err := s.Exec("authelia-backend", []string{"authelia", s.testArg, s.coverageArg, "certificates", "generate", "--host", "*.example.com", "--dir", "/tmp/", "--ecdsa-curve", "invalid"})
		is.True(err != nil)
		is.True(strings.Contains(output, "Failed to generate private key: unrecognized elliptic curve: \"invalid\""))
	})

	o.Spec("TestShouldGenerateCertificateECDSAP224", func(t *testing.T, s *CommandSuite) {
		is := is.New(t)
		output, err := s.Exec("authelia-backend", []string{"authelia", s.testArg, s.coverageArg, "certificates", "generate", "--host", "*.example.com", "--dir", "/tmp/", "--ecdsa-curve", "P224"})
		is.NoErr(err)
		is.True(strings.Contains(output, "Certificate Public Key written to /tmp/cert.pem"))
		is.True(strings.Contains(output, "Certificate Private Key written to /tmp/key.pem"))
	})

	o.Spec("TestShouldGenerateCertificateECDSAP256", func(t *testing.T, s *CommandSuite) {
		is := is.New(t)
		output, err := s.Exec("authelia-backend", []string{"authelia", s.testArg, s.coverageArg, "certificates", "generate", "--host", "*.example.com", "--dir", "/tmp/", "--ecdsa-curve", "P256"})
		is.NoErr(err)
		is.True(strings.Contains(output, "Certificate Public Key written to /tmp/cert.pem"))
		is.True(strings.Contains(output, "Certificate Private Key written to /tmp/key.pem"))
	})

	o.Spec("TestShouldGenerateCertificateECDSAP384", func(t *testing.T, s *CommandSuite) {
		is := is.New(t)
		output, err := s.Exec("authelia-backend", []string{"authelia", s.testArg, s.coverageArg, "certificates", "generate", "--host", "*.example.com", "--dir", "/tmp/", "--ecdsa-curve", "P384"})
		is.NoErr(err)
		is.True(strings.Contains(output, "Certificate Public Key written to /tmp/cert.pem"))
		is.True(strings.Contains(output, "Certificate Private Key written to /tmp/key.pem"))
	})

	o.Spec("TestShouldGenerateCertificateECDSAP521", func(t *testing.T, s *CommandSuite) {
		is := is.New(t)
		output, err := s.Exec("authelia-backend", []string{"authelia", s.testArg, s.coverageArg, "certificates", "generate", "--host", "*.example.com", "--dir", "/tmp/", "--ecdsa-curve", "P521"})
		is.NoErr(err)
		is.True(strings.Contains(output, "Certificate Public Key written to /tmp/cert.pem"))
		is.True(strings.Contains(output, "Certificate Private Key written to /tmp/key.pem"))
	})
}
