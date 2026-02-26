package graph

import (
	"mime"
	"strings"
	"time"

	"github.com/miuponn/butler-hub/internal/domain"
	"github.com/miuponn/butler-hub/pkg/utils"
)

// extract headers for normalization from raw graph api headers
func parseHeaders(raw []MessageHeader) domain.EmailHeaders {
	headers := domain.EmailHeaders{}
	for _, h := range raw {
		switch h.Name {
		case "List-Unsubscribe":
			headers.ListUnsubscribeMailto, headers.ListUnsubscribeURL = parseListUnsubscribe(h.Value)
		case "List-ID":
			headers.ListID = strings.TrimSpace((strings.Trim(h.Value, "<>")))
		case "X-Mailer":
			headers.XMailer = strings.TrimSpace(h.Value)
		case "Precedence":
			headers.Precedence = domain.Precedence(strings.TrimSpace(h.Value))
		case "Return-Path":
			headers.ReturnPath = strings.TrimSpace((strings.Trim(h.Value, "<>")))
		case "Authentication-Results":
			parseAuthResults(h.Value, &headers)
		case "Received":
			headers.ReceivedChain = append(headers.ReceivedChain, strings.TrimSpace(h.Value))
		case "Content-Type":
			headers.ContentType = strings.TrimSpace(h.Value)
		case "X-SID-PRA":
			headers.XSIDPRA = strings.ToLower(strings.TrimSpace(h.Value))
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

	email.FromAddress = strings.ToLower(msg.From.Address)
	email.FromDomain = utils.ExtractEmailDomain(msg.From.Address)
	email.FromDisplayName = strings.TrimSpace(msg.From.Name)

	email.SenderAddress = strings.ToLower(msg.Sender.Address)
	email.SenderDomain = utils.ExtractEmailDomain(msg.Sender.Address)

	for _, recipient := range msg.ToRecipients {
		email.ToAddresses = append(email.ToAddresses, strings.ToLower(recipient.Address))
	}
	if len(msg.ReplyTo) > 0 {
		email.ReplyToDomain = utils.ExtractEmailDomain(msg.ReplyTo[0].Address)
	}

	email.HasAttachments = msg.HasAttachments
	email.Importance = domain.Importance(msg.Importance)
	email.HasUnsubscribe = email.Headers.ListUnsubscribeURL != "" || email.Headers.ListUnsubscribeMailto != ""

	if msg.Body.ContentType == "text" {
		email.BodyText = msg.Body.Content
		email.BodyHTML = ""
		// clean text body by stripping quoted replies and whitespace
		email.BodyClean = utils.NormalizeWhitespace(utils.StripQuotedReply((msg.Body.Content)))
		rawLinks := utils.ExtractURLs(msg.Body.Content)
		for _, link := range rawLinks {
			email.LinkDomains = append(email.LinkDomains, utils.ExtractURLDomain(link))
		}
		email.RawLinks = append(email.RawLinks, rawLinks...)
	}

	if msg.Body.ContentType == "html" {
		email.BodyText = ""
		email.BodyHTML = msg.Body.Content
		// extract links and clean text from HTML body
		parsedHTML := utils.ParseHTML(msg.Body.Content)
		email.BodyClean = parsedHTML.TextContent
		for _, link := range parsedHTML.Links {
			email.LinkDomains = append(email.LinkDomains, utils.ExtractURLDomain(link))
		}
		email.RawLinks = append(email.RawLinks, parsedHTML.Links...)
		email.EmbeddedImages = append(email.EmbeddedImages, parsedHTML.Images...)
	}

	// raw preview right now
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

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func parseListUnsubscribe(raw string) (mailto string, url string) {
	dec := mime.WordDecoder{}
	header, err := dec.DecodeHeader(raw)
	if err != nil {
		header = raw
	}
	parts := strings.Split(header, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "<mailto:") {
			mailto = strings.Trim(part[len("<mailto:"):], "<>")
		} else if strings.HasPrefix(part, "<http") {
			url = strings.Trim(part, "<>")
		}
	}
	return mailto, url
}
