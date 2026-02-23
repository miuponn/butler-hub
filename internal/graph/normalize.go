package graph

import (
	"strings"
	"time"

	"github.com/miuponn/butler-hub/internal/domain"
	"golang.org/x/net/publicsuffix"
	// "golang.org/x/net/html"
)

// extract headers for normalization from raw graph api headers
func parseHeaders(raw []MessageHeader) domain.EmailHeaders {
	headers := domain.EmailHeaders{}
	for _, h := range raw {
		switch h.Name {
		case "List-Unsubscribe":
			headers.ListUnsubscribe = h.Value
		case "List-ID":
			headers.ListID = h.Value
		case "X-Mailer":
			headers.XMailer = h.Value
		case "Precedence":
			headers.Precedence = domain.Precedence(h.Value)
		case "Return-Path":
			headers.ReturnPath = h.Value
		case "Authentication-Results":
			parseAuthResults(h.Value, &headers)
		case "Received":
			headers.ReceivedChain = append(headers.ReceivedChain, h.Value)
		case "Content-Type":
			headers.ContentType = h.Value
		}
	}
	return headers
}

// extract individual tokens from auth results header value
func parseAuthResults(value string, headers *domain.EmailHeaders) {
	parts := strings.Split(value, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "spf=") {
			token := strings.Fields(part)[0]
			headers.SPFResult = domain.SPFResult(strings.Split(token, "=")[1])
		} else if strings.HasPrefix(part, "dkim=") {
			token := strings.Fields(part)[0]
			headers.DKIMResult = domain.DKIMResult(strings.Split(token, "=")[1])
		} else if strings.HasPrefix(part, "dmarc=") {
			token := strings.Fields(part)[0]
			headers.DMARCResult = domain.DMARCResult(strings.Split(token, "=")[1])
		}
	}
}

// adapter to convert Graph API Message to internal Email obj
func NormalizeMessage(msg Message) domain.Email {
	email := domain.Email{}
	email.Headers = parseHeaders(msg.InternetMessageHeaders)

	email.ID = msg.ID
	email.Subject = msg.Subject

	email.ReceivedAt = parseTime(msg.ReceivedDateTime)
	email.SentAt = parseTime(msg.SentDateTime)

	email.FromAddress = msg.From.Address
	email.FromDomain = extractDomain(msg.From.Address)
	email.FromDisplayName = msg.From.Name

	email.SenderAddress = msg.Sender.Address
	email.SenderDomain = extractDomain(msg.Sender.Address)

	for _, recipient := range msg.ToRecipients {
		email.ToAddresses = append(email.ToAddresses, recipient.Address)
	}
	if len(msg.ReplyTo) > 0 {
		email.ReplyToDomain = extractDomain(msg.ReplyTo[0].Address)
	}

	email.HasAttachments = msg.HasAttachments
	email.Importance = domain.Importance(msg.Importance)
	email.HasUnsubscribe = email.Headers.ListUnsubscribe != ""
	// TODO: LinkDomains - requires HTML parsing of body

	if msg.Body.ContentType == "text" {
		email.BodyText = msg.Body.Content
		email.BodyHTML = ""
	}
	if msg.Body.ContentType == "html" {
		email.BodyText = ""
		email.BodyHTML = msg.Body.Content
	}
	email.BodyPreview = msg.BodyPreview

	email.Categories = msg.Categories
	email.IsDraft = msg.IsDraft
	email.IsRead = msg.IsRead
	email.IsReadReceiptRequested = msg.IsReadReceiptRequested

	email.ParentFolderID = msg.ParentFolderID
	email.ConversationID = msg.ConversationID
	email.InternetMsgID = msg.InternetMessageID

	email.Metadata = domain.Metadata{
		Source:     "Microsoft Graph",
		RawWebLink: msg.WebLink,
	}

	return email
}

// helper funcs
func extractDomain(address string) string {
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

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
