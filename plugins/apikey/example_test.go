package apikey_test

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/apikey"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

// API keys let a user's scripts and services call the API without a
// browser session. Keys are stored hashed; the plaintext is returned
// exactly once, at creation.
//
// A key authenticates as its owner, so it is subject to the same
// session guards as a cookie — banning a user disables their keys too.
func ExampleNew() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		Plugins: []godevauth.Plugin{
			apikey.New(apikey.Options{
				HeaderName:         "x-api-key",
				KeyPrefix:          "gda_",
				DefaultKeyLength:   32,
				MaximumKeysPerUser: 10,
				// Persist lastRequest/requestCount at most this often;
				// a negative value keeps key-authenticated requests
				// free of writes altogether.
				UsageWriteInterval: time.Minute,
			}),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, rt := range auth.Routes() {
		if strings.HasPrefix(rt.Path, "/api-key/") {
			fmt.Println(rt.Method, auth.Config().BasePath+rt.Path)
		}
	}

	// Output:
	// POST /api/auth/api-key/create
	// GET /api/auth/api-key/get
	// GET /api/auth/api-key/list
	// POST /api/auth/api-key/update
	// POST /api/auth/api-key/delete
	// POST /api/auth/api-key/verify
}

// Creating a key from a session, then using it in place of one.
func Example_authenticateWithAKey() {
	auth, err := godevauth.New(godevauth.Config{
		BaseURL:  "https://example.com",
		Secret:   "0kMd0Rr0Zt7ZDlk1zVJd3M0h1nQ0FpQ2ZQ0lXbCk3Yg=",
		Database: memory.New(),
		EmailAndPassword: godevauth.EmailPasswordConfig{
			Enabled: true,
		},
		Plugins: []godevauth.Plugin{apikey.New(apikey.Options{KeyPrefix: "gda_"})},
	})
	if err != nil {
		log.Fatal(err)
	}

	call := func(method, path, body string, cookies []*http.Cookie, headers map[string]string) (*http.Response, map[string]any) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		auth.Handler().ServeHTTP(rec, req)
		res := rec.Result()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res, out
	}

	signUp, _ := call(http.MethodPost, "/api/auth/sign-up/email",
		`{"email":"ada@example.com","password":"correct-horse","name":"Ada"}`, nil, nil)

	// The plaintext key is in this response and nowhere else, ever.
	_, created := call(http.MethodPost, "/api/auth/api-key/create",
		`{"name":"deploy-bot"}`, signUp.Cookies(), nil)
	key, _ := created["key"].(string)
	fmt.Println("prefixed:", strings.HasPrefix(key, "gda_"))

	// A request carrying the key is treated as that user's session — no
	// cookie involved.
	_, session := call(http.MethodGet, "/api/auth/get-session", "", nil,
		map[string]string{"x-api-key": key})
	user, _ := session["user"].(map[string]any)
	fmt.Println("acting as:", user["email"])

	// Output:
	// prefixed: true
	// acting as: ada@example.com
}
