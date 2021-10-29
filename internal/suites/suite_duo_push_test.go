package suites

import (
	"context"
	"testing"
	"time"

	"github.com/poy/onpar"
)

func TestDuoPushSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping suite test in short mode")
	}

	o := onpar.New()
	defer o.Run(t)

	o.Group("TestDuoPushRedirectionURLScenario", func() {
		o.BeforeEach(func(t *testing.T) (*testing.T, RodSuite) {
			s := setupTest(t, "", false)
			return t, s
		})

		o.AfterEach(func(t *testing.T, s RodSuite) {
			teardownTest(s)
		})

		o.Spec("TestUserIsRedirectedToDefaultURL", func(t *testing.T, s RodSuite) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer func() {
				cancel()
				s.collectScreenshot(t.Name(), ctx.Err(), s.Page)
			}()

			ConfigureDuo(t, Allow)

			s.doLoginOneFactor(t, s.Context(ctx), testUsername, testPassword, false, "")
			s.doChangeMethod(t, s.Context(ctx), "push-notification")
			s.verifyIsHome(t, s.Page)
		})
	})

	methods = []string{
		"TIME-BASED ONE-TIME PASSWORD",
		"PUSH NOTIFICATION",
	}

	TestRunAvailableMethodsScenario(t)
	TestRunUserPreferencesScenario(t)
	t.Run("TestShouldSucceedAuthentication", TestShouldSucceedAuthentication)
	t.Run("TestShouldFailAuthentication", TestShouldFailAuthentication)
}

func TestShouldSucceedAuthentication(t *testing.T) {
	s := setupTest(t, "", false)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)

	defer func() {
		cancel()
		s.collectScreenshot(t.Name(), ctx.Err(), s.Page)
		teardownDuoTest(t, s)
		teardownTest(s)
	}()

	ConfigureDuo(t, Allow)

	s.doLoginOneFactor(t, s.Context(ctx), testUsername, testPassword, false, "")
	s.doChangeMethod(t, s.Context(ctx), "push-notification")
	s.verifyIsHome(t, s.Context(ctx))
}

func TestShouldFailAuthentication(t *testing.T) {
	s := setupTest(t, "", false)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)

	defer func() {
		cancel()
		s.collectScreenshot(t.Name(), ctx.Err(), s.Page)
		teardownDuoTest(t, s)
		teardownTest(s)
	}()

	ConfigureDuo(t, Deny)

	s.doLoginOneFactor(t, s.Context(ctx), testUsername, testPassword, false, "")
	s.doChangeMethod(t, s.Context(ctx), "push-notification")
	s.WaitElementLocatedByClassName(t, s.Context(ctx), "failure-icon")
}
