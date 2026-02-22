package graph

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"golang.org/x/oauth2"
)

type Client struct {
	Token      *oauth2.Token
	BaseURL    string
	HTTPClient *http.Client
}

type Body struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}

type EmailAddress struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

type Recipient struct {
	EmailAddress `json:"emailAddress"`
}

type Flag struct {
	FlagStatus string `json:"flagStatus"`
}

type Message struct {
	ID                      string      `json:"id"`
	InternetMessageID       string      `json:"internetMessageId"`
	ChangeKey               string      `json:"changeKey"`
	Subject                 string      `json:"subject"`
	CreatedDateTime         string      `json:"createdDateTime"`
	LastModifiedDateTime    string      `json:"lastModifiedDateTime"`
	ReceivedDateTime        string      `json:"receivedDateTime"`
	SentDateTime            string      `json:"sentDateTime"`
	HasAttachments          bool        `json:"hasAttachments"`
	Importance              string      `json:"importance"`
	From                    Recipient   `json:"from"`
	Sender                  Recipient   `json:"sender"`
	ToRecipients            []Recipient `json:"toRecipients"`
	ReplyTo                 []Recipient `json:"replyTo"`
	Categories              []string    `json:"categories"`
	IsRead                  bool        `json:"isRead"`
	IsDraft                 bool        `json:"isDraft"`
	ParentFolderID          string      `json:"parentFolderId"`
	ConversationID          string      `json:"conversationId"`
	ConversationIndex       string      `json:"conversationIndex"`
	InferenceClassification string      `json:"inferenceClassification"`
	IsReadReceiptRequested  bool        `json:"isReadReceiptRequested"`
	Flag                    Flag        `json:"flag"`
	WebLink                 string      `json:"webLink"`
	BodyPreview             string      `json:"bodyPreview"`
	Body                    Body        `json:"body"`
}

type messagesResponse struct {
	Value    []Message `json:"value"`
	NextLink string    `json:"@odata.nextLink"`
}

type QueryOptions struct {
	Top      int
	Filter   string
	Select   string
	NextLink string
}

// client to initialize graph api requests using OAuth token
func NewClient(token *oauth2.Token) Client {
	ctx := context.Background()
	httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	return Client{
		Token:      token,
		BaseURL:    "https://graph.microsoft.com/v1.0",
		HTTPClient: httpClient,
	}
}

// method to get messages from Graph API
func (c Client) GetMessages(options QueryOptions) ([]Message, string, error) {
	var requestURL string

	// build request URL based on params
	if options.NextLink != "" {
		requestURL = options.NextLink
	} else {
		params := url.Values{}
		if options.Top > 0 {
			params.Add("$top", strconv.Itoa(options.Top))
		}
		if options.Filter != "" {
			params.Set("$filter", options.Filter)
		}
		if options.Select != "" {
			params.Set("$select", options.Select)
		}
		requestURL = c.BaseURL + "/me/messages?" + params.Encode()
	}
	// make request to Graph API
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	// decode raw JSON response into Go struct
	var messagesResp messagesResponse

	err = json.NewDecoder(resp.Body).Decode(&messagesResp)
	if err != nil {
		return nil, "", err
	}
	return messagesResp.Value, messagesResp.NextLink, nil

}
