package apache

import (
	"bufio"
	"net/url"
	"os"
	"strings"
	"unicode"
)

type ServerBlock struct {
	ServerNames []string
	ListenPorts []int
	Root        string
	ProxyPass   []string
	FileSource  string
}

type Parser struct {
	resolver   *Resolver
	warnings   *[]string
	blocks     []*ServerBlock
	maxDepth   int
	maxTargets int
}

func NewParser(baseRoot string, warnings *[]string) *Parser {
	return &Parser{
		resolver:   NewResolver(baseRoot),
		warnings:   warnings,
		maxDepth:   5,
		maxTargets: 50,
	}
}

func (p *Parser) ParseMain(entry string) []*ServerBlock {
	paths := p.resolver.Resolve(entry, entry, p.warnings)
	if len(paths) > 0 {
		p.parseFile(paths[0], 0, nil)
	}
	return p.blocks
}

func (p *Parser) parseFile(filePath string, depth int, currentServer **ServerBlock) {
	if depth > p.maxDepth {
		addWarning(p.warnings, "apache: include depth exceeded")
		return
	}

	f, err := os.Open(filePath)
	if err != nil {
		addWarning(p.warnings, "apache: file read permission denied")
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var activeServer *ServerBlock
	if currentServer != nil && *currentServer != nil {
		activeServer = *currentServer
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle basic tokenization per line
		tokens := tokenizeLine(line)
		if len(tokens) == 0 {
			continue
		}

		directive := strings.ToLower(tokens[0])

		if strings.HasPrefix(directive, "<virtualhost") {
			activeServer = &ServerBlock{FileSource: filePath}
			p.blocks = append(p.blocks, activeServer)
			continue
		}

		if directive == "</virtualhost>" {
			activeServer = nil
			continue
		}

		if directive == "include" || directive == "includeoptional" {
			if len(tokens) > 1 {
				incPattern := tokens[1]
				paths := p.resolver.Resolve(filePath, incPattern, p.warnings)
				for _, incPath := range paths {
					p.parseFile(incPath, depth+1, &activeServer)
				}
			}
			continue
		}

		if activeServer == nil {
			continue // ignore global directives other than include
		}

		switch directive {
		case "servername":
			if len(tokens) > 1 {
				activeServer.ServerNames = append(activeServer.ServerNames, tokens[1])
			}
		case "serveralias":
			if len(tokens) > 1 {
				for i := 1; i < len(tokens); i++ {
					activeServer.ServerNames = append(activeServer.ServerNames, tokens[i])
				}
			}
		case "documentroot":
			if len(tokens) > 1 {
				activeServer.Root = strings.Trim(tokens[1], `"'`)
			}
		case "proxypass", "proxypassreverse":
			if len(tokens) > 2 {
				target := tokens[2]
				if len(activeServer.ProxyPass) < p.maxTargets {
					cleanTarget := redactURL(target)
					activeServer.ProxyPass = append(activeServer.ProxyPass, cleanTarget)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		addWarning(p.warnings, "apache: file read error")
	}

	if currentServer != nil {
		*currentServer = activeServer
	}
}

func tokenizeLine(line string) []string {
	var tokens []string
	var current strings.Builder
	inString := false
	var stringChar rune

	for i := 0; i < len(line); i++ {
		c := rune(line[i])

		if inString {
			if c == '\\' && i+1 < len(line) {
				current.WriteRune(rune(line[i+1]))
				i++
				continue
			}
			if c == stringChar {
				inString = false
				tokens = append(tokens, current.String())
				current.Reset()
				continue
			}
			current.WriteRune(c)
			continue
		}

		if c == '\'' || c == '"' {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			inString = true
			stringChar = c
			continue
		}

		if unicode.IsSpace(c) {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			continue
		}

		current.WriteRune(c)
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		// fallback redaction
		if idx := strings.Index(raw, "@"); idx != -1 {
			schemeIdx := strings.Index(raw, "://")
			if schemeIdx != -1 && schemeIdx < idx {
				return raw[:schemeIdx+3] + "REDACTED@" + raw[idx+1:]
			}
		}
		return raw
	}
	if u.User != nil {
		u.User = url.User("REDACTED")
	}
	return u.String()
}
