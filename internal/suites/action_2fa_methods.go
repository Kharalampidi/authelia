package suites

import (
	"fmt"
	"testing"

	"github.com/go-rod/rod"
)

func (rs *RodSession) doChangeMethod(t *testing.T, page *rod.Page, method string) {
	rs.WaitElementLocatedByCSSSelector(t, page, "methods-button").MustClick()
	rs.WaitElementLocatedByCSSSelector(t, page, "methods-dialog")
	rs.WaitElementLocatedByCSSSelector(t, page, fmt.Sprintf("%s-option", method)).MustClick()
}
