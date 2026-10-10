package apache

import (
	"context"
	"strings"
	"net"

	"vpsmonitoring-agent/internal/discovery/models"
)

type Collector struct {
	baseRoots []string
}

// NewCollector accepts multiple possible roots for Apache config
func NewCollector(baseRoots []string) *Collector {
	return &Collector{
		baseRoots: baseRoots,
	}
}

func (c *Collector) Collect(ctx context.Context) ([]models.WebsiteCandidate, []string) {
	var warnings []string
	var allResults []models.WebsiteCandidate

	defer func() {
		if r := recover(); r != nil {
			addWarning(&warnings, "panic recovered during apache discovery")
		}
	}()

	websiteMap := make(map[string]*models.WebsiteCandidate)

	for _, root := range c.baseRoots {
		// Try standard entrypoints in this root
		entrypoints := []string{
			root + "/apache2.conf",
			root + "/httpd.conf",
			root + "/conf/httpd.conf",
		}

		var blocks []*ServerBlock
		var parsed bool
		for _, entry := range entrypoints {
			parser := NewParser(root, &warnings)
			b := parser.ParseMain(entry)
			if len(b) > 0 || len(parser.resolver.parsedFiles) > 0 {
				blocks = b
				parsed = true
				break
			}
		}

		if !parsed {
			continue // try next root
		}

		for _, block := range blocks {
			if len(block.ServerNames) == 0 {
				block.ServerNames = []string{"_"} // Default if empty
			}

			// Determine primary domain: prefer first non‑IP, non‑infrastructure name
			var primary string = ""
			for _, name := range block.ServerNames {
				lower := strings.ToLower(name)
				if lower == "_" || lower == "default" || lower == "localhost" {
					continue
				}
				if net.ParseIP(lower) != nil {
					// skip IPs unless we have no other candidate
					continue
				}
				primary = lower
				break
			}
			if primary == "" {
				// fallback to first entry (could be IP or infrastructure)
				primary = strings.ToLower(block.ServerNames[0])
				if primary == "" {
					primary = "_"
				}
			}


			cand, exists := websiteMap[primary]
			if !exists {
				cand = &models.WebsiteCandidate{
					WebServerKind: models.ServiceApache,
					Source:        models.SourceApacheConfig,
					Confidence:    models.ConfidenceLow,
				}
				websiteMap[primary] = cand
				cand.Domains = append(cand.Domains, models.WebDomainCandidate{
					Name:      primary,
					IsPrimary: true,
				})
			} else {
				// If existing primary is an IP and the new primary is a hostname, replace it
				existingPrimary := ""
				for _, d := range cand.Domains {
					if d.IsPrimary {
						existingPrimary = d.Name
						break
					}
				}
				isIP := func(s string) bool { return net.ParseIP(s) != nil }
				if isIP(existingPrimary) && !isIP(primary) && primary != "_" && primary != "default" && primary != "localhost" {
					// replace primary domain entry with hostname
					cand.Domains = []models.WebDomainCandidate{{Name: primary, IsPrimary: true}}
				}
			}


			// Merge aliases
			for i := 1; i < len(block.ServerNames); i++ {
				alias := strings.ToLower(block.ServerNames[i])
				if alias == "" {
					continue
				}
				found := false
				for _, d := range cand.Domains {
					if d.Name == alias {
						found = true
						break
					}
				}
				if !found {
					cand.Domains = append(cand.Domains, models.WebDomainCandidate{
						Name:      alias,
						IsPrimary: false,
					})
				}
			}

			// Merge ports
			for _, port := range block.ListenPorts {
				found := false
				for _, p := range cand.ListenPorts {
					if p == port {
						found = true
						break
					}
				}
				if !found {
					cand.ListenPorts = append(cand.ListenPorts, port)
				}
			}

			// Root (first one wins generally)
			if cand.DocumentRoot == "" && block.Root != "" {
				cand.DocumentRoot = block.Root
			}

			// Proxy Targets
			for _, target := range block.ProxyPass {
				found := false
				for _, t := range cand.ProxyPassTargets {
					if t == target {
						found = true
						break
					}
				}
				if !found {
					cand.ProxyPassTargets = append(cand.ProxyPassTargets, target)
				}
			}

			// Evidence
			foundEv := false
			for _, ev := range cand.Evidence {
				if ev.Value == block.FileSource {
					foundEv = true
					break
				}
			}
			if !foundEv && block.FileSource != "" {
				cand.Evidence = append(cand.Evidence, models.Evidence{
					Kind:  "apache_virtualhost",
					Value: block.FileSource,
				})
			}
		}
	}

	for primary, cand := range websiteMap {
		// Calculate Confidence
		if primary != "_" && primary != `""` {
			if cand.DocumentRoot != "" || len(cand.ProxyPassTargets) > 0 {
				cand.Confidence = models.ConfidenceHigh
			} else {
				cand.Confidence = models.ConfidenceMedium
			}
		} else {
			cand.Confidence = models.ConfidenceLow
		}
		allResults = append(allResults, *cand)
	}

	return allResults, warnings
}
