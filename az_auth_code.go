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
	// Check for stored credentials
	if a.token != nil {
		// Check if expired & attempt refresh if expired
		if a.isExpired() {
			err := a.getToken(ctx, opts)
			if err != nil {
				return azcore.AccessToken{}, err
			}
		}
	} else {
		// No Stored Credentials
		err := a.getToken(ctx, opts)
		if err != nil {
			return azcore.AccessToken{}, err
		}
	}

	expires, err := strconv.ParseInt(a.token.ExpiresOn, 10, 64)
	if err != nil {
		return azcore.AccessToken{}, err
	}

	return azcore.AccessToken{Token: a.token.AccessToken, ExpiresOn: time.Unix(expires, 0)}, nil
}

// GetIdToken returns or requests a valid ID Token from Azure Active Directory.
func (a *AuthCodeCredential) GetIdToken() (string, error) {
	// TODO
	return "", errors.New("")
}

func (a *AuthCodeCredential) getToken(ctx context.Context, opts policy.TokenRequestOptions) error {
	// Start channel and waitgroup for auth events
	channels.InitChannels()
	var wg sync.WaitGroup
	wg.Add(1)

	// Ensure we have valid scopes
	if len(opts.Scopes) == 0 {
		return errors.New(credNameDeviceCode + ": GetToken() requires at least one scope")
	}

	//Start Server
	srv := server.BuildServer("9999")
	srv.StartServer()

	//Get Auth URL
	err := a.options.UrlCallback(ctx, azrequests.AzRequestsClient.GetAuthURL(opts.Scopes, "123456"))
	if err != nil {
		return err
	}

	// Wait for response
	go func() {
		a.token = <-channels.AuthEvents
		srv.StopServer()
		wg.Done()
	}()
	wg.Wait()

	return nil
}

func (a *AuthCodeCredential) isExpired() bool {
	expired := true
	expires, err := strconv.ParseInt(a.token.ExpiresOn, 10, 64)
	if err != nil {
		return expired
	}

	// Attempt Refresh if expired
	if expires > time.Now().Unix() {
		expired = false
	}

	return expired
}

var _ azcore.TokenCredential = (*AuthCodeCredential)(nil)
