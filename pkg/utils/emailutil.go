package utils

import (
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// extract registered domain from email address
func ExtractEmailDomain(address string) string {
	parts := strings.Split(address, "@")
	if len(parts) != 2 {
		return ""
	}
	registeredDomain, err := publicsuffix.EffectiveTLDPlusOne(parts[1])
	if err != nil {
		return ""
	}
	return registeredDomain
}

// extract local part from email address
func ExtractLocalPart(address string) string {
	parts := strings.Split(address, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

// extract registered domain from URL
func ExtractURLDomain(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	registeredDomain, err := publicsuffix.EffectiveTLDPlusOne(parsedURL.Hostname())
	if err != nil {
		return ""
	}
	return registeredDomain
}
