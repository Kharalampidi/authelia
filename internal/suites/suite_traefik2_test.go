package suites

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/matryer/is"
	"github.com/poy/onpar"
)

func TestTraefik2Suite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping suite test in short mode")
	}

	o := onpar.New()
	defer o.Run(t)

	s := setupTest(t, "", true)
	teardownTest(s)

	o.BeforeEach(func(t *testing.T) (*testing.T, RodSuite) {
		s := setupTest(t, "", false)
		return t, s
	})

	o.AfterEach(func(t *testing.T, s RodSuite) {
		teardownTest(s)
	})

	o.Spec("TestShouldKeepSessionAfterRedisRestart", func(t *testing.T, s RodSuite) {
		is := is.New(t)
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer func() {
			cancel()
			s.collectScreenshot(t.Name(), ctx.Err(), s.Page)
		}()

		s.doLoginTwoFactor(t, s.Context(ctx), testUsername, testPassword, false, secret, "")

		s.doVisit(s.Context(ctx), fmt.Sprintf("%s/secret.html", SecureBaseURL))
		s.verifySecretAuthorized(t, s.Context(ctx))

		err := traefik2DockerEnvironment.Restart("redis")
		is.NoErr(err)

		s.doVisit(s.Context(ctx), fmt.Sprintf("%s/secret.html", SecureBaseURL))
		s.verifySecretAuthorized(t, s.Context(ctx))
	})

	TestRunOneFactorScenario(t)
	TestRunTwoFactorScenario(t)
	TestRunCustomHeadersScenario(t)
}
