package classifier

import (
	_ "embed"
	"regexp"
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

//go:embed data/urgent_keywords.txt
var urgentKeywordsRaw string
var urgentKeywordsRe *regexp.Regexp

//go:embed data/promotional_keywords.txt
var promotionalKeywordsRaw string
var promotionalKeywordsRe *regexp.Regexp

//go:embed data/transactional_keywords.txt
var transactionalKeywordsRaw string
var transactionalKeywordsRe *regexp.Regexp

//go:embed data/financial_request_patterns.txt
var financialRequestPatternsRaw string
var financialRequestPatternsRe *regexp.Regexp

//go:embed data/threat_language_patterns.txt
var threatLanguagePatternsRaw string
var threatLanguagePatternsRe *regexp.Regexp

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
	urgentKeywords := []string{}
	lines = strings.Split(urgentKeywordsRaw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line[0] != '#' {
			urgentKeywords = append(urgentKeywords, regexp.QuoteMeta(line))
		}
	}
	if len(urgentKeywords) > 0 {
		urgentKeywordsRe = regexp.MustCompile(`(?i)\b(` + strings.Join(urgentKeywords, "|") + `)\b`)
	}
	promotionalKeywords := []string{}
	lines = strings.Split(promotionalKeywordsRaw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line[0] != '#' {
			promotionalKeywords = append(promotionalKeywords, regexp.QuoteMeta(line))
		}
	}
	if len(promotionalKeywords) > 0 {
		promotionalKeywordsRe = regexp.MustCompile(`(?i)\b(` + strings.Join(promotionalKeywords, "|") + `)\b`)
	}
	transactionalKeywords := []string{}
	lines = strings.Split(transactionalKeywordsRaw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line[0] != '#' {
			transactionalKeywords = append(transactionalKeywords, regexp.QuoteMeta(line))
		}
	}
	if len(transactionalKeywords) > 0 {
		transactionalKeywordsRe = regexp.MustCompile(`(?i)\b(` + strings.Join(transactionalKeywords, "|") + `)\b`)
	}
	financialRequestPatterns := []string{}
	lines = strings.Split(financialRequestPatternsRaw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line[0] != '#' {
			financialRequestPatterns = append(financialRequestPatterns, line)
		}
	}
	if len(financialRequestPatterns) > 0 {
		financialRequestPatternsRe = regexp.MustCompile(`(?i)(` + strings.Join(financialRequestPatterns, "|") + `)`)
	}
	threatLanguagePatterns := []string{}
	lines = strings.Split(threatLanguagePatternsRaw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line[0] != '#' {
			threatLanguagePatterns = append(threatLanguagePatterns, line)
		}
	}
	if len(threatLanguagePatterns) > 0 {
		threatLanguagePatternsRe = regexp.MustCompile(`(?i)(` + strings.Join(threatLanguagePatterns, "|") + `)`)
	}
}

// main feature extraction method, takes normalized email and produces feature vector for classification
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
	if urgentKeywordsRe != nil {
		features.UrgentKeywordsSubjectCount = len(urgentKeywordsRe.FindAllString(email.Subject, -1))
		features.UrgentKeywordsBodyCount = len(urgentKeywordsRe.FindAllString(email.BodyClean, -1))
	}
	if threatLanguagePatternsRe != nil {
		features.ThreatLanguagePatternsSubjectCount = len(threatLanguagePatternsRe.FindAllString(email.Subject, -1))
		features.ThreatLanguagePatternsBodyCount = len(threatLanguagePatternsRe.FindAllString(email.BodyClean, -1))
	}
	if financialRequestPatternsRe != nil {
		features.FinancialRequestPatternsSubjectCount = len(financialRequestPatternsRe.FindAllString(email.Subject, -1))
		features.FinancialRequestPatternsBodyCount = len(financialRequestPatternsRe.FindAllString(email.BodyClean, -1))
	}
	if promotionalKeywordsRe != nil {
		features.PromotionalKeywordsCount = len(promotionalKeywordsRe.FindAllString(email.BodyClean, -1))
	}
	if transactionalKeywordsRe != nil {
		features.TransactionalKeywordsCount = len(transactionalKeywordsRe.FindAllString(email.BodyClean, -1))
	}

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
