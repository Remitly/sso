package auth

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path"

	"github.com/buzzfeed/sso/internal/auth/providers"
	"github.com/buzzfeed/sso/internal/pkg/aead"
	"github.com/buzzfeed/sso/internal/pkg/groups"
	"github.com/buzzfeed/sso/internal/pkg/sessions"

	"github.com/datadog/datadog-go/statsd"
)

func newProvider(pc ProviderConfig, sc SessionConfig) (providers.Provider, error) {
	p := &providers.ProviderData{
		ProviderSlug:       pc.ProviderSlug,
		Scope:              pc.Scope,
		ClientID:           pc.ClientConfig.ID,
		ClientSecret:       pc.ClientConfig.Secret,
		SessionLifetimeTTL: sc.SessionLifetimeTTL,
	}

	var singleFlightProvider providers.Provider
	switch pc.ProviderType {
	case providers.GoogleProviderName: // Google
		gpc := pc.GoogleProviderConfig
		p.ApprovalPrompt = gpc.ApprovalPrompt

		if gpc.Credentials != "" {
			_, err := os.Open(gpc.Credentials)
			if err != nil {
				return nil, fmt.Errorf("invalid Google credentials file: %s", gpc.Credentials)
			}
		}

		googleProvider, err := providers.NewGoogleProvider(p, gpc.Impersonate, gpc.Credentials)
		if err != nil {
			return nil, err
		}

		cache := groups.NewFillCache(googleProvider.PopulateMembers, pc.GroupCacheConfig.Interval.Refresh)
		googleProvider.GroupsCache = cache

		singleFlightProvider = providers.NewSingleFlightProvider(googleProvider)
	case providers.OktaProviderName:
		opc := pc.OktaProviderConfig

		oktaProvider, err := providers.NewOktaProvider(p, opc.OrgURL, opc.ServerID)
		if err != nil {
			return nil, err
		}

		tags := []string{"provider:okta"}
		cache := providers.NewGroupCache(oktaProvider, pc.GroupCacheConfig.Interval.Provider, oktaProvider.StatsdClient, tags)
		singleFlightProvider = providers.NewSingleFlightProvider(cache)
	case "test":
		return providers.NewTestProvider(nil), nil
	default:
		return nil, fmt.Errorf("unimplemented provider.type: %q", pc.ProviderType)
	}

	return singleFlightProvider, nil
}

// SetProvider is a function that takes a provider and assigns it to the authenticator.
func SetProvider(provider providers.Provider) func(*Authenticator) error {
	return func(a *Authenticator) error {
		a.provider = provider
		return nil
	}
}

// SetStatsdClient is function that takes in a statsd client and assigns it to the
// authenticator and provider.
func SetStatsdClient(statsdClient *statsd.Client) func(*Authenticator) error {
	return func(a *Authenticator) error {
		a.StatsdClient = statsdClient

		if a.provider != nil {
			a.provider.SetStatsdClient(statsdClient)
		}

		return nil
	}
}

// SetRedirectURL takes an identity provider slug to construct the
// url callback using the slug and configured redirect url.
func SetRedirectURL(serverConfig ServerConfig, slug string) func(*Authenticator) error {
	return func(a *Authenticator) error {
		a.redirectURL = &url.URL{
			Scheme: serverConfig.Scheme,
			Host:   serverConfig.Host,
			Path:   path.Join(slug, "callback"),
		}
		return nil
	}
}

// SetValidator sets the email validator
func SetValidator(validator func(string) bool) func(*Authenticator) error {
	return func(a *Authenticator) error {
		a.Validator = validator
		return nil
	}
}

// SetCookieStore sets the cookie store to use a miscreant cipher
func SetCookieStore(sessionConfig SessionConfig, providerSlug string) func(*Authenticator) error {
	return func(a *Authenticator) error {
		decodedKey, err := base64.StdEncoding.DecodeString(sessionConfig.Key)
		if err != nil {
			return err
		}

		codeCipher, err := aead.NewMiscreantCipher([]byte(decodedKey))
		if err != nil {
			return err
		}

		cc := sessionConfig.CookieConfig
		decodedCookieSecret, err := base64.StdEncoding.DecodeString(cc.Secret)
		if err != nil {
			return err
		}

		cookieName := fmt.Sprintf("%s_%s", cc.Name, providerSlug)
		cookieStore, err := sessions.NewCookieStore(cookieName,
			sessions.CreateMiscreantCookieCipher(decodedCookieSecret),
			func(c *sessions.CookieStore) error {
				c.CookieDomain = cc.Domain
				c.CookieHTTPOnly = cc.HTTPOnly
				c.CookieExpire = cc.Expire
				c.CookieSecure = cc.Secure
				return nil
			})

		if err != nil {
			return err
		}

		a.csrfStore = cookieStore
		a.sessionStore = cookieStore
		a.AuthCodeCipher = codeCipher
		return nil
	}
}

// SetRedisStore sets the session store to use redis
func SetRedisStore(sessionConfig SessionConfig, providerSlug string) func(*Authenticator) error {
	return func(a *Authenticator) error {
		decodedKey, err := base64.StdEncoding.DecodeString(sessionConfig.Key)
		if err != nil {
			return err
		}

		codeCipher, err := aead.NewMiscreantCipher([]byte(decodedKey))
		if err != nil {
			return err
		}

		cc := sessionConfig.CookieConfig
		rc := sessionConfig.RedisConfig
		decodedCookieSecret, err := base64.StdEncoding.DecodeString(cc.Secret)
		if err != nil {
			return err
		}

		cookieName := fmt.Sprintf("%s_%s", cc.Name, providerSlug)
		redisStore, err := sessions.NewRedisStore(cookieName,
			func(c *sessions.RedisStore) error {
				return sessions.CreateMiscreantCookieCipher(decodedCookieSecret)(&c.CookieStore)
			},
			func(c *sessions.RedisStore) error {
				if rc.UseSentinel {
					c.UseSentinel = rc.UseSentinel
					c.SentinelMasterName = rc.SentinelMasterName
					c.SentinelConnectionURLs = rc.ConnectionURLs
				} else {
					c.UseSentinel = rc.UseSentinel
					c.ConnectionURL = rc.ConnectionURLs[0]
				}

				c.CookieDomain = cc.Domain
				c.CookieHTTPOnly = cc.HTTPOnly
				c.CookieExpire = cc.Expire
				c.CookieSecure = cc.Secure
				return nil
			})

		if err != nil {
			return err
		}

		a.csrfStore = redisStore
		a.sessionStore = redisStore
		a.AuthCodeCipher = codeCipher
		return nil
	}
}
