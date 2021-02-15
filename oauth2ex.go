// Heavily tailored from golang.org/x/oauth2/oauth2.go
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/context/ctxhttp"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// tokenJSON is the struct representing the HTTP response from OAuth2
// providers returning a token in JSON form.
type tokenJSON struct {
	AccessToken string `json:"access_token"`
}

// newTokenRequest returns a new *http.Request to retrieve a new token
// from tokenURL using the provided clientID, clientSecret, and POST
// body parameters.
//
// inParams is whether the clientID & clientSecret should be encoded
// as the POST body. An 'inParams' value of true means to send it in
// the POST body (along with any values in v); false means to send it
// in the Authorization header.
func newTokenRequest(tokenURL, clientID, clientSecret string, v url.Values) (*http.Request, error) {
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	return req, nil
}

// retrieveToken takes a *Config and uses that to retrieve an *internal.tokenSimplified.
// This token is then mapped from *internal.tokenSimplified into an *oauth2.tokenSimplified which is returned along
// with an error..
func retrieveToken(ctx context.Context, c *oauth2.Config, v url.Values) (string, error) {
	req, err := newTokenRequest(c.Endpoint.TokenURL, c.ClientID, c.ClientSecret, v)
	if err != nil {
		return "", err
	}
	tk, err := doTokenRoundTrip(ctx, req)
	if err != nil {
		if rErr, ok := err.(*retrieveError); ok {
			return "", rErr
		}
		return "", err
	}
	return tk, nil
}

func doTokenRoundTrip(ctx context.Context, req *http.Request) (string, error) {
	r, err := ctxhttp.Do(ctx, http.DefaultClient, req)
	if err != nil {
		return "", err
	}
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	_ = r.Body.Close()
	if err != nil {
		return "", fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return "", &retrieveError{
			Response: r,
			Body:     body,
		}
	}

	var token string
	content, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch content {
	case "application/x-www-form-urlencoded", "text/plain":
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return "", err
		}
		token = values.Get("access_token")
	default:
		var tj tokenJSON
		if err = json.Unmarshal(body, &tj); err != nil {
			return "", err
		}
		token = tj.AccessToken
	}
	if token == "" {
		return "", errors.New("oauth2: server response missing access_token")
	}
	return token, nil
}

// retrieveError is the error returned when the token endpoint returns a
// non-2XX HTTP status code.
type retrieveError struct {
	Response *http.Response
	// Body is the body that was consumed by reading Response.Body.
	// It may be truncated.
	Body []byte
}

func (r *retrieveError) Error() string {
	return fmt.Sprintf("oauth2: cannot fetch token: %v\nResponse: %s", r.Response.Status, r.Body)
}

// passwordCredentialsTokenEx converts a resource owner username and password
// pair into a token.
//
// Per the RFC, this grant type should only be used "when there is a high
// degree of trust between the resource owner and the client (e.g., the client
// is part of the device operating system or a highly privileged application),
// and when other authorization grant types are not available."
// See https://tools.ietf.org/html/rfc6749#section-4.3 for more info.
//
// The HTTP client to use is derived from the context.
// If nil, http.DefaultClient is used.
func passwordCredentialsTokenEx(ctx context.Context, c oauth2.Config, username, password, otp, scope string, parameters url.Values) (string, error) {
	values := url.Values{
		"grant_type": {"password"},
		"username":   {username},
		"password":   {password},
	}

	if len(otp) > 0 {
		values.Set("totp", otp)
	}

	if len(scope) > 0 {
		values.Set("scope", scope)
	}

	if parameters != nil {
		for k, v := range parameters {
			values[k] = v
		}
	}

	return retrieveToken(ctx, &c, values)
}
