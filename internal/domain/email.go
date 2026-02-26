package domain

import (
	"time"
)

type Metadata struct {
	Source     string
	RawWebLink string
}

// normalized SPF result
type SPFResult string

const (
	SPFNone     SPFResult = "none"
	SPFNeutral  SPFResult = "neutral"
	SPFPass     SPFResult = "pass"
	SPFFail     SPFResult = "fail"
	SPFSoftFail SPFResult = "softfail"

	SPFTempError SPFResult = "temperror"
	SPFPermError SPFResult = "permerror"
)

// normalized DKIM result
type DKIMResult string

const (
	DKIMNone      DKIMResult = "none"
	DKIMPass      DKIMResult = "pass"
	DKIMFail      DKIMResult = "fail"
	DKIMTempError DKIMResult = "temperror"
	DKIMPermError DKIMResult = "permerror"
)

// normalized DMARC result
type DMARCResult string

const (
	DMARCNone      DMARCResult = "none"
	DMARCPass      DMARCResult = "pass"
	DMARCFail      DMARCResult = "fail"
	DMARCTempError DMARCResult = "temperror"
	DMARCPermError DMARCResult = "permerror"
)

// normalized Precedence value
type Precedence string

const (
	PrecedenceBulk Precedence = "bulk"
	PrecedenceList Precedence = "list"
	PrecedenceJunk Precedence = "junk"
)

type EmailHeaders struct {
	// broadcast signals
	ListUnsubscribeURL    string // high value braodcast signal
	ListUnsubscribeMailto string // high value broadcast signal
	ListID                string // broadcast signal, mailing list identifier
	XMailer               string // mass mailer - weak broadcast signal
	XSIDPRA               string // good for spoofing checks

	Precedence Precedence // broadcast indicator ex. bulk, list, junk
	ReturnPath string     // for domain mismatch

	// auth signals
	SPFResult   SPFResult
	DKIMResult  DKIMResult
	DMARCResult DMARCResult

	ReceivedChain []string // raw for now
	ContentType   string   // for body parsing decisions

}

// normalized Importance value
type Importance string

const (
	LowImportance    Importance = "low"
	NormalImportance Importance = "normal"
	HighImportance   Importance = "high"
)

type Email struct {
	ID      string
	Subject string

	ReceivedAt time.Time
	SentAt     time.Time

	FromAddress     string
	FromDomain      string
	FromDisplayName string

	SenderAddress string
	SenderDomain  string

	ReplyToDomain string
	ToAddresses   []string

	HasAttachments bool
	Importance     Importance
	HasUnsubscribe bool
	LinkDomains    []string

	RawLinks       []string
	EmbeddedImages []string

	BodyText    string
	BodyHTML    string
	BodyPreview string
	BodyClean   string

	Categories             []string
	IsDraft                bool
	IsRead                 bool
	IsReadReceiptRequested bool

	ConversationID string
	ParentFolderID string
	InternetMsgID  string

	Metadata Metadata
	Headers  EmailHeaders
}
