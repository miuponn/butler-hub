package utils

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

var urlRegex = regexp.MustCompile(`https?://[^\s<>"]+`)

// parsed HTML struct has clean text content, list of links, and list of images
type ParsedHTML struct {
	TextContent string
	Links       []string
	Images      []string
}

// html parser - init strings builder for text content, calls html node walker, then normalizes
func ParseHTML(input string) ParsedHTML {
	sb := strings.Builder{}

	parsedHTML := ParsedHTML{}
	root, err := html.Parse(strings.NewReader(input))
	if err != nil {
		return parsedHTML
	}
	walk(root, &parsedHTML, &sb)

	parsedHTML.TextContent = strings.TrimSpace(NormalizeWhitespace(StripQuotedReply(sb.String())))
	return parsedHTML

}

// html node walker - recursively traverse html nodes, adds links and images to parsed html struct
func walk(n *html.Node, result *ParsedHTML, sb *strings.Builder) {
	switch {
	case n.Type == html.TextNode:
		sb.WriteString(html.UnescapeString(n.Data) + " ")
	case n.Type == html.ElementNode && n.Data == "a":
		for _, attr := range n.Attr {
			if attr.Key == "href" {
				result.Links = append(result.Links, attr.Val)
			}
		}
	case n.Type == html.ElementNode && n.Data == "img":
		for _, attr := range n.Attr {
			if attr.Key == "src" {
				result.Images = append(result.Images, attr.Val)
			}
		}
	// skip script and style tags and blockquotes
	case n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style" || n.Data == "blockquote"):
		return
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c, result, sb)
	}

}

// helper func - removes quoted reply text
func StripQuotedReply(body string) string {
	lines := strings.Split(body, "\n")
	cleanLines := []string{}

	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), ">") {
			continue
		}
		cleanLines = append(cleanLines, line)
	}
	return strings.Join(cleanLines, "\n")
}

// helper func - split on whitespace and rejoin to normalize spacing
func NormalizeWhitespace(s string) string {
	lines := strings.Fields(s)
	return strings.Join(lines, " ")
}

// helper func - extract URLs from text using regex
func ExtractURLs(text string) []string {
	return urlRegex.FindAllString(text, -1)
}
