package suites

import (
	"context"
	"testing"
	"time"

	"github.com/matryer/is"
	"github.com/poy/onpar"
)

func TestRunOIDCScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping suite test in short mode")
	}

	o := onpar.New()
	defer o.Run(t)

	o.Group("TestOIDCScenario", func() {
		o.BeforeEach(func(t *testing.T) (*testing.T, RodSuite) {
			s := setupTest(t, "", false)
			return t, s
		})

		o.AfterEach(func(t *testing.T, s RodSuite) {
			teardownTest(s)
		})

		o.Spec("TestShouldAuthorizeAccessToOIDCApp", func(t *testing.T, s RodSuite) {
			is := is.New(t)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer func() {
				cancel()
				s.collectScreenshot(t.Name(), ctx.Err(), s.Page)
			}()

			s.doVisit(s.Context(ctx), OIDCBaseURL)
			s.verifyIsFirstFactorPage(t, s.Context(ctx))
			s.doFillLoginPageAndClick(t, s.Context(ctx), testUsername, testPassword, false)
			s.verifyIsSecondFactorPage(t, s.Context(ctx))
			s.doValidateTOTP(t, s.Context(ctx), secret)

			s.waitBodyContains(t, s.Context(ctx), "Not logged yet...")

			// Search for the 'login' link
			err := s.Page.MustSearch("Log in").Click("left")
			is.NoErr(err)

			s.verifyIsConsentPage(t, s.Context(ctx))
			err = s.WaitElementLocatedByCSSSelector(t, s.Context(ctx), "accept-button").Click("left")
			is.NoErr(err)

			// Verify that the app is showing the info related to the user stored in the JWT token
			s.waitBodyContains(t, s.Context(ctx), "Logged in as john!")
		})

		o.Spec("TestShouldDenyConsent", func(t *testing.T, s RodSuite) {
			is := is.New(t)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer func() {
				cancel()
				s.collectScreenshot(t.Name(), ctx.Err(), s.Page)
			}()

			s.doVisit(s.Context(ctx), OIDCBaseURL)
			s.verifyIsFirstFactorPage(t, s.Context(ctx))
			s.doFillLoginPageAndClick(t, s.Context(ctx), testUsername, testPassword, false)
			s.verifyIsSecondFactorPage(t, s.Context(ctx))
			s.doValidateTOTP(t, s.Context(ctx), secret)

			s.waitBodyContains(t, s.Context(ctx), "Not logged yet...")

			// Search for the 'login' link
			err := s.Page.MustSearch("Log in").Click("left")
			is.NoErr(err)

			s.verifyIsConsentPage(t, s.Context(ctx))

			err = s.WaitElementLocatedByCSSSelector(t, s.Context(ctx), "deny-button").Click("left")
			is.NoErr(err)

			s.verifyIsOIDC(t, s.Context(ctx), "oauth2:", "https://oidc.example.com:8080/oauth2/callback?error=access_denied&error_description=User%20has%20rejected%20the%20scopes")
		})
	})
}
