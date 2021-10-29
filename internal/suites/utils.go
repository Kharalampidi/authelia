package suites

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-rod/rod"
)

// GetLoginBaseURL returns the URL of the login portal and the path prefix if specified.
func GetLoginBaseURL() string {
	if PathPrefix != "" {
		return LoginBaseURL + PathPrefix
	}

	return LoginBaseURL
}

func (rs *RodSession) collectCoverage(page *rod.Page) {
	coverageDir := "../../web/.nyc_output"
	now := time.Now()

	resp, err := page.Eval("JSON.stringify(window.__coverage__)")
	if err != nil {
		log.Fatal(err)
	}

	coverageData := fmt.Sprintf("%v", resp.Value)

	_ = os.MkdirAll(coverageDir, 0775)

	if coverageData != "<nil>" {
		err = ioutil.WriteFile(fmt.Sprintf("%s/coverage-%d.json", coverageDir, now.Unix()), []byte(coverageData), 0664) //nolint:gosec
		if err != nil {
			log.Fatal(err)
		}

		err = filepath.Walk("../../web/.nyc_output", fixCoveragePath)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func (rs *RodSession) collectScreenshot(name string, err error, page *rod.Page) {
	if err == context.DeadlineExceeded {
		base := "/buildkite/screenshots"
		build := os.Getenv("BUILDKITE_BUILD_NUMBER")
		suite := strings.ToLower(os.Getenv("SUITE"))
		job := os.Getenv("BUILDKITE_JOB_ID")
		path := filepath.Join(fmt.Sprintf("%s/%s/%s/%s", base, build, suite, job))

		if err := os.MkdirAll(path, 0755); err != nil {
			log.Fatal(err)
		}

		page.MustScreenshotFullPage(fmt.Sprintf("%s/%s.jpg", path, strings.ReplaceAll(name, "/", "-")))
	}
}

func fixCoveragePath(path string, file os.FileInfo, err error) error {
	if err != nil {
		return err
	}

	if file.IsDir() {
		return nil
	}

	coverage, err := filepath.Match("*.json", file.Name())

	if err != nil {
		return err
	}

	if coverage {
		read, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		wd, _ := os.Getwd()
		ciPath := strings.TrimSuffix(wd, "internal/suites")
		content := strings.ReplaceAll(string(read), "/node/src/app/", ciPath+"web/")

		err = ioutil.WriteFile(path, []byte(content), 0)
		if err != nil {
			return err
		}
	}

	return nil
}

func setupTest(t *testing.T, proxy string, register bool) RodSuite {
	s := RodSuite{}

	browser, err := StartRodWithProxy(proxy)
	if err != nil {
		log.Fatal(err)
	}

	s.RodSession = browser

	if proxy == "" {
		s.Page = s.doCreateTab(HomeBaseURL)
		s.verifyIsHome(t, s.Page)
	}

	if register {
		secret = s.doLoginAndRegisterTOTP(t, s.Page, testUsername, testPassword, false)
	}

	return s
}

func setupCLITest() (s *CommandSuite) {
	s = &CommandSuite{}

	dockerEnvironment := NewDockerEnvironment([]string{
		"internal/suites/docker-compose.yml",
		"internal/suites/CLI/docker-compose.yml",
		"internal/suites/example/compose/authelia/docker-compose.backend.{}.yml",
	})
	s.DockerEnvironment = dockerEnvironment

	testArg := ""
	coverageArg := ""

	if os.Getenv("CI") == stringTrue {
		testArg = "-test.coverprofile=/authelia/coverage-$(date +%s).txt"
		coverageArg = "COVERAGE"
	}

	s.testArg = testArg
	s.coverageArg = coverageArg

	return s
}

func teardownTest(s RodSuite) {
	s.collectCoverage(s.Page)
	s.MustClose()
	err := s.RodSession.Stop()

	if err != nil {
		log.Fatal(err)
	}
}

func teardownDuoTest(t *testing.T, s RodSuite) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer func() {
		cancel()
		s.collectScreenshot(t.Name(), ctx.Err(), s.Page)
	}()

	s.doLogout(t, s.Context(ctx))
	s.doLoginOneFactor(t, s.Context(ctx), "john", "password", false, "")
	s.verifyIsSecondFactorPage(t, s.Context(ctx))
	s.doChangeMethod(t, s.Context(ctx), "one-time-password")
	s.WaitElementLocatedByCSSSelector(t, s.Context(ctx), "one-time-password-method")
}
