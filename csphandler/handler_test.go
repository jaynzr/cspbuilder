package csphandler_test

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/jaynzr/cspbuilder"
	"github.com/jaynzr/cspbuilder/csphandler"
)

var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	script := "doSomething();"
	nonce := csphandler.Nonce(w)

	csphandler.Hash(w, cspbuilder.Script, cspbuilder.SHA512, script)
	w.Write([]byte(`<script nonce="` + nonce + `">` + script + `</script>`))
})

func TestCsp(t *testing.T) {

	re := regexp.MustCompile(`nonce-(.+?)'`)
	csp := cspbuilder.New()
	csp.New(cspbuilder.Script, cspbuilder.Self, cspbuilder.Nonce)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	csphandler.ContentSecurityPolicy(csp, handler, false).ServeHTTP(res, req)

	cspStr := res.Header().Get("Content-Security-Policy")
	body := res.Body.String()

	t.Log(body)

	matches := re.FindStringSubmatch(cspStr)

	if len(matches) != 2 || !strings.Contains(body, `nonce="` + matches[1] +`"`) {
		t.Fatal("nonce not found", cspStr, body)
	}

	if !strings.Contains(cspStr, "'sha512-JmJZZcyblZQCHlZRsKDDtflAYSRkis0qyVDld8GYYgE33OHeq29ups1mbWGRG5YsUJA8XlUFLdqMMpEYX5m9WA=='") {
		t.Fatal("want 'sha512-JmJZZcyblZQCHlZRsKDDtflAYSRkis0qyVDld8GYYgE33OHeq29ups1mbWGRG5YsUJA8XlUFLdqMMpEYX5m9WA=='", "got", cspStr)
	}
}
