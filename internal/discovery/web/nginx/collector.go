package nginx

import (
	"context"
	"strings"

	"vpsmonitoring-agent/internal/discovery/models"
)

type Collector struct {
	baseRoot string
}

func NewCollector(baseRoot string) *Collector {
	return &Collector{
		baseRoot: baseRoot,
	}
}

func (c *Collector) Collect(ctx context.Context) ([]models.WebsiteCandidate, []string) {
	var warnings []string

	defer func() {
		if r := recover(); r != nil {
			addWarning(&warnings, "panic recovered during nginx discovery")
		}
	}()

	parser := NewParser(c.baseRoot, &warnings)
	blocks := parser.ParseMain(c.baseRoot + "/nginx.conf")

	if len(blocks) == 0 {
		return nil, warnings
	}

	websiteMap := make(map[string]*models.WebsiteCandidate)

	for _, block := range blocks {
		if len(block.ServerNames) == 0 {
			block.ServerNames = []string{"_"} // Default if empty
		}

		primary := strings.ToLower(block.ServerNames[0])
		if primary == "" {
			primary = "_"
		}

		cand, exists := websiteMap[primary]
		if !exists {
			cand = &models.WebsiteCandidate{
				WebServerKind: models.ServiceNginx,
				Source:        models.SourceNginxConfig,
				Confidence:    models.ConfidenceLow,
			}
			websiteMap[primary] = cand
			cand.Domains = append(cand.Domains, models.WebDomainCandidate{
				Name:      primary,
				IsPrimary: true,
			})
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

		// FastCgi Targets
		for _, target := range block.FastCgiPass {
			found := false
			for _, t := range cand.FpmSocketPaths {
				if t == target {
					found = true
					break
				}
			}
			if !found {
				cand.FpmSocketPaths = append(cand.FpmSocketPaths, target)
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
				Kind:  "nginx_server_block",
				Value: block.FileSource,
			})
		}
	}

	var results []models.WebsiteCandidate
	for primary, cand := range websiteMap {
		// Calculate Confidence
		if primary != "_" && primary != `""` {
			if cand.DocumentRoot != "" || len(cand.ProxyPassTargets) > 0 || len(cand.FpmSocketPaths) > 0 {
				cand.Confidence = models.ConfidenceHigh
			} else {
				cand.Confidence = models.ConfidenceMedium
			}
		} else {
			cand.Confidence = models.ConfidenceLow
		}
		results = append(results, *cand)
	}

	return results, warnings
}
