package azrequests

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type Client struct {
	BaseURL   *url.URL
	UserAgent string
	Options   ClientOptions

	httpClient *http.Client
}

type ClientOptions struct {
	TenantID     string
	ClientID     string
	ClientSecret string
}

type Token struct {
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    string `json:"expires_in"`
	ExtExpiresIn string `json:"ext_expires_in"`
	ExpiresOn    string `json:"expires_on"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
}

var AzRequestsClient *Client

func NewClient(httpClient *http.Client, options ClientOptions) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	//Create Base URL
	baseURL, err := url.Parse("https://api.partnercenter.microsoft.com")
	if err != nil {
		log.Fatal("unable")
	}

	AzRequestsClient = &Client{
		BaseURL:    baseURL,
		UserAgent:  "ClearIT",
		Options:    options,
		httpClient: httpClient,
	}
}

func (c *Client) GetAuthURL(scopes []string, state string) string {
	url, err := url.Parse("https://login.microsoftonline.com/" + c.Options.TenantID + "/oauth2/authorize")
	if err != nil {
		log.Println(err)
	}

	params := url.Query()
	params.Set("client_id", c.Options.ClientID)
	params.Set("response_mode", "form_post")
	params.Set("response_type", "code id_token")
	params.Set("scope", strings.Join(scopes, ","))
	params.Set("nonce", "1")
	params.Set("prompt", "consent")
	params.Set("state", state)

	url.RawQuery = params.Encode()

	return url.String()
}

func (c *Client) GetToken(authCode string) (Token, error) {
	tokenURL := "https://login.microsoftonline.com/" + c.Options.TenantID + "/oauth2/token"
	tokenRequest := url.Values{}
	tokenRequest.Set("resource", "https://api.partnercenter.microsoft.com")
	tokenRequest.Set("client_id", c.Options.ClientID)
	tokenRequest.Set("client_secret", c.Options.ClientSecret)
	tokenRequest.Set("grant_type", "authorization_code")
	tokenRequest.Set("code", authCode)

	req, err := c.NewRequest("POST", tokenURL, tokenRequest)
	if err != nil {
		return Token{}, err
	}

	var token Token
	_, err = c.Do(req, &token)
	return token, err
}

func (c *Client) NewRequest(method, path string, body url.Values) (*http.Request, error) {
	u, err := url.Parse(path)
	if err != nil {
		return nil, err
	}

	encodedBody := body.Encode()
	req, err := http.NewRequest(method, u.String(), strings.NewReader(encodedBody))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	return req, nil
}

func (c *Client) Do(req *http.Request, v interface{}) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(v)
	return resp, err
}
