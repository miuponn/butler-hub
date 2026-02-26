package classifier

import (
	_ "embed"
	"strconv"
	"strings"

	"github.com/miuponn/butler-hub/internal/domain"
	"github.com/miuponn/butler-hub/pkg/utils"
)

//go:embed data/shorteners.txt
var shortenerRaw string
var knownShorteners map[string]bool

//go:embed data/tlds.txt
var tldsRaw string
var knownTLDScores map[string]float64

//go:embed data/tlds_known_spam.txt
var tldSpamRaw string
var knownSpamTLDs map[string]bool

func init() {
	knownShorteners = map[string]bool{}
	lines := strings.Split(shortenerRaw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line[0] != '#' {
			knownShorteners[line] = true
		}
	}
	knownTLDScores = map[string]float64{}
	lines = strings.Split(tldsRaw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line[0] != '#' {
			parts := strings.Fields(line)
			if len(parts) == 2 {
				score, err := strconv.ParseFloat(parts[1], 64)
				if err == nil {
					tld := parts[0]
					knownTLDScores[tld] = score
				}
			}
		}
	}
	knownSpamTLDs = map[string]bool{}
	lines = strings.Split(tldSpamRaw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line[0] != '#' {
			knownSpamTLDs[line] = true
		}
	}
}

func ExtractFeatures(email domain.Email) Features {
	features := Features{}

	// structural
	features.LinkCount = len(email.LinkDomains)
	features.UniqueLinkDomains = UniqueLinkDomains(email.LinkDomains)
	features.ImageCount = len(email.EmbeddedImages)
	features.HasAttachments = email.HasAttachments
	for _, link := range email.RawLinks {
		if HasTrackingParams(link) {
			features.HasTrackingParams = true
			break
		}
	}
	if HasTrackingParams(email.Headers.ListUnsubscribeURL) {
		features.HasTrackingParams = true
	}

	// header signal
	features.HasListUnsubscribeHeader = email.HasUnsubscribe
	features.PrecedenceBulk = email.Headers.Precedence == domain.PrecedenceBulk
	features.ReplyToMismatch = email.FromDomain != email.ReplyToDomain && email.ReplyToDomain != ""
	// TODO: DisplayNameSpoofing

	// domain signals
	features.SenderDomainMismatch = email.FromDomain != email.SenderDomain && email.SenderDomain != ""
	// TODO: DomainReputationScore
	returnPathDomain := utils.ExtractEmailDomain(email.Headers.ReturnPath)
	features.ReturnPathDomainMismatch = email.FromDomain != returnPathDomain && email.FromDomain != "" && returnPathDomain != ""
	// TODO: DisposableDomainList
	// TODO: NewlyRegisteredDomain
	tld := utils.ExtractTLD(email.FromDomain)
	if score, ok := knownTLDScores[tld]; ok {
		features.SuspiciousTLDScore = score
	} else if knownSpamTLDs[tld] {
		features.SuspiciousTLDScore = 0.6
	}
	// TODO: DomainSpoofing

	// content signals
	// TODO: ContainsPromoKeywords
	// TODO: ContainsTransactionalKeywords
	// TODO: ContainsUrgentKeywords
	// TODO: FinancialRequestPatternsDetected
	// TODO: ThreatLanguagePatternsDetected
	features.WordCount = len(strings.Fields((email.BodyClean)))

	// entropy and obfuscation signals
	// TODO: HighLocalPartEntropy
	// TODO: HighSubjectEntropy
	// TODO: HighSymbolDensity
	// TODO: MixedUnicodeScripts
	for _, link := range email.RawLinks {
		URLDomain := utils.ExtractURLDomain(link)
		if knownShorteners[URLDomain] {
			features.URLShortenerUsed = true
			break
		}
	}

	// behavioural
	features.IsReply = strings.HasPrefix(email.Subject, "Re:") || strings.HasPrefix(email.Subject, "RE:")
	features.IsForward = strings.HasPrefix(email.Subject, "Fwd:") || strings.HasPrefix(email.Subject, "FW:")

	// auth signals
	features.SPFResult = email.Headers.SPFResult
	features.DKIMResult = email.Headers.DKIMResult
	features.DMARCResult = email.Headers.DMARCResult

	return features
}

// deduplicator for link domains
func UniqueLinkDomains(domains []string) []string {
	seen := map[string]bool{}
	for _, d := range domains {
		if d != "" {
			seen[d] = true
		}
	}
	unique := []string{}
	for d := range seen {
		unique = append(unique, d)
	}
	return unique
}

func HasTrackingParams(url string) bool {
	trackingParams := []string{"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content"}
	for _, param := range trackingParams {
		if strings.Contains(url, param+"=") {
			return true
		}
	}
	return false
}
