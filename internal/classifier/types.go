package classifier

import (
	"github.com/miuponn/butler-hub/internal/domain"
)

type Classifier struct {
	SuspicionGroups []SignalGroup
	SuspicionPolicy SuspicionPolicy
}

// Note: centralized features result after feature extraction pass
// Note: extracted signals used for scoring after featureextraction()
// what features engins are allowed to use, pre-normalized, pre-canonicalized, deterministic
// single source of truth for all engines
// NOTE: future proof, one day can replace IntentEngine with model-backed implmentation
// without touching SuscpiciousEngine, etc. Decoupled

// NOTE: Before tuning: log feature vector, final decision, confidence, user override
// Analyze: false positives, ambiguous cases. etc. tune weights

// Step 1: Feature extraction result

type Features struct {
	// structural
	LinkCount int
	// could break this down into link count, etc
	UniqueLinkDomains []string // keep as slice for intent/category engines, or refine to signals?
	ImageCount        int
	HasTrackingParams bool
	HasAttachments    bool

	// header signals
	HasListUnsubscribeHeader bool
	PrecedenceBulk           bool
	ReplyToMismatch          bool // overlap with SPF/DKIM/DMARC?
	DisplayNameSpoofing      bool // overlap with SPF/DKIM/DMARC?

	// domain signals
	SenderDomainMismatch     bool    // (sender ≠ from). overlap with SPF/DKIM/DMARC?
	ReturnPathDomainMismatch bool    // overlap with SPF/DKIM/DMARC?
	DisposableDomainList     bool    // overlap with SPF/DKIM/DMARC?
	NewlyRegisteredDomain    bool    // if good external tool exists
	SuspiciousTLDScore       float64 // possible overlap
	DomainSpoofing           bool    // overlap with SPF/DKIM/DMARC?

	// content signals
	UrgentKeywordsSubjectCount           int
	UrgentKeywordsBodyCount              int
	ThreatLanguagePatternsSubjectCount   int
	ThreatLanguagePatternsBodyCount      int
	FinancialRequestPatternsSubjectCount int
	FinancialRequestPatternsBodyCount    int
	PromotionalKeywordsCount             int
	TransactionalKeywordsCount           int
	WordCount                            int
	DomainReputationScore                float64 // overlap with SPF/DKIM/DMARC?

	// entropy and obfuscation signnals
	HighLocalPartEntropy bool
	HighSubjectEntropy   bool
	HighSymbolDensity    bool
	MixedUnicodeScripts  bool
	URLShortenerUsed     bool

	// behavioural
	IsReply   bool
	IsForward bool

	// auth signals
	SPFResult   domain.SPFResult
	DKIMResult  domain.DKIMResult
	DMARCResult domain.DMARCResult
}

type SignalGroup struct {
	Name     string
	Signals  map[string]float64
	MaxScore float64
}

// Step 2: Suspicious Engine (hard gate)
// NOTE: if flagged (policy decision), return result immediately from pipeline
// focus precision over recall- false positives costly

type Signal struct {
	// consider adding computed field for contribution weight x value ?
	Name   string
	Weight float64 // contribution score: w x v
	Value  float64 // per-email strength: 0.0 - 1.0
	Reason string
}

// will need to normalize weights and guarantee bounded signal count
// otherwise remove hardcoded max constant or will have hidden coupling
const MaxSuspicionScore float64 = 10.0

// Suspicion result post suspicionengine(features)
type SuspicionResult struct {
	Flagged bool
	Score   float64
	Signals []Signal
}

// policy decoupled from result, allows flexible threshold configuration
type SuspicionPolicy struct {
	MediumThreshold   float64
	HighThreshold     float64
	CriticalThreshold float64
}

type SeverityLevel int

const (
	Low SeverityLevel = iota
	Medium
	High
	Critical
)

// method to determine severity level based on score and policy thresholds
func (s SuspicionResult) Severity(policy SuspicionPolicy) SeverityLevel {
	switch {
	case s.Score >= policy.CriticalThreshold:
		return Critical
	case s.Score >= policy.HighThreshold:
		return High
	case s.Score >= policy.MediumThreshold:
		return Medium
	default:
		return Low
	}
}

// Step 3. Intent Engine
// intent scores post intentengine(features)
// select max score above threshold, if all below threshold,
// classify as UnknownIntent to avoid. rule ordering bias
type IntentScores struct {
	Transactional float64
	Broadcast     float64
	Personal      float64
}

// Step 4. Subcategory engine (Content-Focused)
// only run if intent == broadcast, transactional. etc.
// Lower confidence expectations, softer layer

// Step 5. Final Result Object

type IntentType string

const (
	UnknownIntent       IntentType = "Unknown"
	TransactionalIntent IntentType = "Transactional"
	BroadcastIntent     IntentType = "Broadcast"
	PersonalIntent      IntentType = "Personal"
)

type CategoryType string

// broadcast: promotional, newsletter/digest, intstitutional, community/event,
// transactional: financial, account/security, shipping/logistics
// cross-intent categories: work/professional, education, social/platform notifications
// probably will refine later and test/focus on building first suspicious engine

type ClassificationResult struct {
	Suspicious SuspicionResult

	IntentScores IntentScores
	IntentType   IntentType // argmax intent scores, if all below threshold, "Unknown"

	CategoryScores map[string]float64 // subcategory scores, only for certain intents
	CategoryType   string             // argmax category scores, if all below threshold, "Unknown"

	// must replace- no probabilistic model - need to have documented formula
	// margin between top intent scores? normalized suspicious score? weighted certainty?
	// aggregated confidence across layers?
	// NEED TO BE EDITED
	Confidence float64
	Reasons    []string // human readable reasons for classification, can be derived from signals
}
