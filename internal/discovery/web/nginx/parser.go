package nginx

import (
	"os"
	"strconv"
	"strings"
	"unicode"
)

type ServerBlock struct {
	ServerNames []string
	ListenPorts []int
	Root        string
	ProxyPass   []string
	FastCgiPass []string
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
	// Must initialize base tracking
	paths := p.resolver.Resolve(entry, entry, p.warnings)
	if len(paths) > 0 {
		p.parseFile(paths[0], 0)
	}
	return p.blocks
}

func (p *Parser) parseFile(filePath string, depth int) {
	if depth > p.maxDepth {
		addWarning(p.warnings, "include depth exceeded")
		return
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		addWarning(p.warnings, "nginx: file read permission denied")
		return
	}

	tokens := tokenize(string(data))
	p.parseTokens(tokens, filePath, depth)
}

func tokenize(data string) []string {
	var tokens []string
	var current strings.Builder
	inString := false
	var stringChar rune

	for i := 0; i < len(data); i++ {
		c := rune(data[i])

		if inString {
			if c == '\\' && i+1 < len(data) {
				current.WriteRune(rune(data[i+1]))
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

		if c == '#' {
			for i < len(data) && data[i] != '\n' {
				i++
			}
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

		if c == '{' || c == '}' || c == ';' {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			tokens = append(tokens, string(c))
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

func (p *Parser) parseTokens(tokens []string, filePath string, depth int) {
	var currentServer *ServerBlock
	var braceScope int
	var serverBraceScope int = -1

	for i := 0; i < len(tokens); i++ {
		token := tokens[i]

		if token == "{" {
			braceScope++
			continue
		}
		if token == "}" {
			braceScope--
			if braceScope < 0 {
				addWarning(p.warnings, "nginx: unmatched braces in configuration")
				return // Abort file parsing gracefully
			}
			if serverBraceScope != -1 && braceScope < serverBraceScope {
				// Server block ended
				serverBraceScope = -1
				currentServer = nil
			}
			continue
		}

		// Look ahead to the semicolon or brace to get arguments
		args := []string{}
		j := i + 1
		stmtEnd := -1
		for ; j < len(tokens); j++ {
			if tokens[j] == ";" {
				stmtEnd = j
				break
			}
			if tokens[j] == "{" || tokens[j] == "}" {
				// A directive usually ends with ; or a block {. We don't advance i past the {, so loop handles {} normally.
				stmtEnd = j
				break
			}
			args = append(args, tokens[j])
		}

		if token == "server" && j < len(tokens) && tokens[j] == "{" {
			currentServer = &ServerBlock{FileSource: filePath}
			p.blocks = append(p.blocks, currentServer)
			serverBraceScope = braceScope + 1
			i = j - 1 // Will be incremented by loop and then `{` handled
			continue
		}

		if token == "include" {
			if stmtEnd == -1 || tokens[stmtEnd] != ";" {
				addWarning(p.warnings, "nginx: malformed configuration at include")
				return
			}
			if len(args) > 0 {
				paths := p.resolver.Resolve(filePath, args[0], p.warnings)
				for _, incPath := range paths {
					p.parseFile(incPath, depth+1)
				}
			}
			i = stmtEnd
			continue
		}

		if currentServer == nil {
			// Not inside a server block, ignore directives like http, events
			if stmtEnd != -1 && tokens[stmtEnd] == ";" {
				i = stmtEnd
			}
			continue
		}

		// Inside server block (or nested location block)
		if stmtEnd == -1 || tokens[stmtEnd] != ";" {
			// If it's a block like "location / {", we let the `{` logic handle it in next iterations.
			if stmtEnd != -1 && tokens[stmtEnd] == "{" {
				// Allowed (e.g. location, if). Advance to just before `{`
				i = stmtEnd - 1
				continue
			} else {
				addWarning(p.warnings, "nginx: malformed configuration missing semicolon")
				return
			}
		}

		switch token {
		case "server_name":
			currentServer.ServerNames = append(currentServer.ServerNames, args...)
		case "listen":
			if len(args) > 0 {
				port := parseListenPort(args[0])
				if port > 0 {
					currentServer.ListenPorts = append(currentServer.ListenPorts, port)
				}
			}
		case "root":
			if len(args) > 0 && currentServer.Root == "" { // keep first defined (or could be nested, but we just take simple representation)
				currentServer.Root = args[0]
			}
		case "proxy_pass":
			if len(args) > 0 && len(currentServer.ProxyPass) < p.maxTargets {
				currentServer.ProxyPass = append(currentServer.ProxyPass, stripCredentials(args[0]))
			}
		case "fastcgi_pass":
			if len(args) > 0 && len(currentServer.FastCgiPass) < p.maxTargets {
				currentServer.FastCgiPass = append(currentServer.FastCgiPass, args[0])
			}
		}

		i = stmtEnd
	}
}

func parseListenPort(arg string) int {
	// args can be 80, 127.0.0.1:8080, [::]:443
	if strings.Contains(arg, "]:") {
		parts := strings.Split(arg, "]:")
		if len(parts) == 2 {
			p, _ := strconv.Atoi(parts[1])
			return p
		}
	} else if strings.Contains(arg, ":") {
		parts := strings.Split(arg, ":")
		p, _ := strconv.Atoi(parts[len(parts)-1])
		return p
	} else {
		p, _ := strconv.Atoi(arg)
		return p
	}
	return 0
}

func stripCredentials(urlStr string) string {
	// very basic basic-auth stripping
	if strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://") {
		parts := strings.SplitN(urlStr, "://", 2)
		if len(parts) == 2 {
			hostPart := parts[1]
			if idx := strings.Index(hostPart, "@"); idx != -1 {
				return parts[0] + "://" + hostPart[idx+1:]
			}
		}
	}
	return urlStr
}
