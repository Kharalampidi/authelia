package suites

import (
	"strings"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/matryer/is"
	"github.com/pquerna/otp/totp"
)

func (rs *RodSession) doRegisterTOTP(t *testing.T, page *rod.Page) string {
	is := is.New(t)

	rs.WaitElementLocatedByCSSSelector(t, page, "register-link").MustClick()
	rs.verifyMailNotificationDisplayed(t, page)

	link := doGetLinkFromLastMail(t)
	rs.doVisit(page, link)

	secretURL := page.MustElement("#secret-url").MustAttribute("value")
	secret := (*secretURL)[strings.LastIndex(*secretURL, "=")+1:]
	is.True(secret != "")

	return secret
}

func (rs *RodSession) doEnterOTP(t *testing.T, page *rod.Page, code string) {
	inputs := rs.WaitElementsLocatedByCSSSelector(t, page, "otp-input input")

	for i := 0; i < 6; i++ {
		_ = inputs[i].Input(string(code[i]))
	}
}

func (rs *RodSession) doValidateTOTP(t *testing.T, page *rod.Page, secret string) {
	is := is.New(t)
	code, err := totp.GenerateCode(secret, time.Now())
	is.NoErr(err)
	rs.doEnterOTP(t, page, code)
}
