package gincsp_test

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/jaynzr/cspbuilder"
	"github.com/jaynzr/cspbuilder/csphandler/gincsp"
)

func TestCsp(t *testing.T) {

	re := regexp.MustCompile(`nonce-(.+?)'`)
	csp := cspbuilder.New()
	csp.New(cspbuilder.Script, cspbuilder.Self, cspbuilder.Nonce)

	router := gin.New()
	router.Use(gincsp.ContentSecurityPolicy(csp, false))
	router.GET("/foo", func(c *gin.Context) {
		script := "doSomething();"
		nonce := gincsp.Nonce(c)

		gincsp.Hash(c, cspbuilder.Script, cspbuilder.SHA512, script)
		c.String(http.StatusOK, `
		<script>`+script+`</script>
		<script nonce="`+nonce+`">doAnother()</script>`)
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	router.ServeHTTP(res, req)

	cspStr := res.Header().Get("Content-Security-Policy")
	body := res.Body.String()

	t.Log(body)

	matches := re.FindStringSubmatch(cspStr)

	if len(matches) != 2 || !strings.Contains(body, `nonce="`+matches[1]+`"`) {
		t.Fatal("nonce not found", cspStr, body)
	}

	if !strings.Contains(cspStr, "'sha512-JmJZZcyblZQCHlZRsKDDtflAYSRkis0qyVDld8GYYgE33OHeq29ups1mbWGRG5YsUJA8XlUFLdqMMpEYX5m9WA=='") {
		t.Fatal("want 'sha512-JmJZZcyblZQCHlZRsKDDtflAYSRkis0qyVDld8GYYgE33OHeq29ups1mbWGRG5YsUJA8XlUFLdqMMpEYX5m9WA=='", "got", cspStr)
	}
}
