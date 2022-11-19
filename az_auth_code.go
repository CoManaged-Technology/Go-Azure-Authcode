// Copyright (c) Open MSP Solutions. All rights reserved.
// Licensed under the MIT License.
package azauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/openmspsolutions/go-azure-authcode/internal/azrequests"
	"github.com/openmspsolutions/go-azure-authcode/internal/channels"
	"github.com/openmspsolutions/go-azure-authcode/internal/server"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

const credNameDeviceCode = "AuthCodeCredential"

// DeviceCodeCredentialOptions contains optional parameters for DeviceCodeCredential.
type AuthCodeCredentialOptions struct {
	azcore.ClientOptions

	// TenantID is the Azure Active Directory tenant the credential authenticates in. Defaults to the
	// "organizations" tenant, which can authenticate work and school accounts. Required for single-tenant
	// applications.
	TenantID string
	// ClientID is the ID of the application users will authenticate to.
	ClientID string
	// ClientSecret is the Secret of the application users will authenticate to.
	ClientSecret string
	// UrlCallback controls how the credential handles the authentication url. The credential calls
	// this function with authentication details when it receives a device code. By default, the credential
	// prints these url to stdout.
	UrlCallback func(context.Context, string) error
}

func (o *AuthCodeCredentialOptions) init() {
	if o.TenantID == "" {
		o.TenantID = "organizations"
	}

	if o.UrlCallback == nil {
		o.UrlCallback = func(ctx context.Context, url string) error {
			fmt.Println(url)
			return nil
		}
	}
}

// DeviceCodeCredential acquires tokens for a user via the device code flow, which has the
// user browse to an Azure Active Directory URL, enter a code, and authenticate. It's useful
// for authenticating a user in an environment without a web browser, such as an SSH session.
// If a web browser is available, InteractiveBrowserCredential is more convenient because it
// automatically opens a browser to the login page.
type AuthCodeCredential struct {
	token   *azrequests.Token
	options *AuthCodeCredentialOptions
}

// NewAuthCodeCredential creates a DeviceCodeCredential. Pass nil to accept default options.
func NewAuthCodeCredential(options *AuthCodeCredentialOptions) (*AuthCodeCredential, error) {
	if options == nil {
		return nil, errors.New("InvalidOptions: The options passed to NewAuthCodeCredential must not be nil")
	}
	options.init()

	// Create azrequests client
	azClientOptions := azrequests.ClientOptions{
		TenantID:     options.TenantID,
		ClientID:     options.ClientID,
		ClientSecret: options.ClientSecret,
	}
	azrequests.NewClient(http.DefaultClient, azClientOptions)

	authCodeCred := &AuthCodeCredential{options: options}

	return authCodeCred, nil
}

// GetToken returns or requests an access token from Azure Active Directory.
// This method is called automatically by Azure SDK clients.
func (a *AuthCodeCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	// Start channel and waitgroup for auth events
	channels.InitChannels()
	var wg sync.WaitGroup
	wg.Add(1)

	// Check for stored credentials
	if a.token != nil {
		isValid := false
		// Check if expired

		// Attempt Refresh if expired

		// If token is valid or was refreshed return it
		if isValid {
			expires, err := strconv.ParseInt(a.token.ExpiresOn, 10, 64)
			if err != nil {
				return azcore.AccessToken{}, err
			}

			return azcore.AccessToken{Token: a.token.AccessToken, ExpiresOn: time.Unix(expires, 0)}, nil
		}
	}

	// Credentials are not valid, get new token
	//

	// Ensure we have valid scopes
	if len(opts.Scopes) == 0 {
		return azcore.AccessToken{}, errors.New(credNameDeviceCode + ": GetToken() requires at least one scope")
	}

	//Start Server
	server.BuildServer("9999").StartServer()

	//Get Auth URL
	err := a.options.UrlCallback(ctx, azrequests.AzRequestsClient.GetAuthURL(opts.Scopes, "123456"))
	if err != nil {
		return azcore.AccessToken{}, err
	}

	// Wait for response
	go func() {
		a.token = <-channels.AuthEvents
		wg.Done()
	}()
	wg.Wait()

	// If token is valid or was refreshed return it
	isValid := true
	if isValid {
		expires, err := strconv.ParseInt(a.token.ExpiresOn, 10, 64)
		if err != nil {
			return azcore.AccessToken{}, err
		}

		return azcore.AccessToken{Token: a.token.AccessToken, ExpiresOn: time.Unix(expires, 0)}, nil
	}

	// Something went wrong, return general error
	return azcore.AccessToken{}, errors.New("there was an error completing the login attempt, please try again or contact support")
}

// GetIdToken returns or requests a valid ID Token from Azure Active Directory.
func (a *AuthCodeCredential) GetIdToken() (string, error) {
	// TODO
	return "", errors.New("")
}

var _ azcore.TokenCredential = (*AuthCodeCredential)(nil)
