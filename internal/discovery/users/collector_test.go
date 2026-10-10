package users

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"vpsmonitoring-agent/internal/discovery/models"
)

func TestParseWebDomainsOutputText(t *testing.T) {
	sampleOutput := `DOMAIN IP TPL SSL DISK BW SPND DATE
------- -- --- --- ---- -- ---- ----
payment.ibridge.digital 209.182.233.252 default yes 357 10 no 2025-02-26
ibridge.digital 209.182.233.252 default yes 9522 5835 no 2025-02-26
signage.ibridge.digital 209.182.233.252 default yes 847 109 yes 2025-02-26
office.ibridge.digital 209.182.233.252 default yes 2242 16 no 2025-02-26
arcus2025.ibridge.digital 209.182.233.252 default yes 1636 498 yes 2025-05-19
ibd2025.ibridge.digital 209.182.233.252 default yes 2595 12 yes 2025-05-19
indusvalley2025.ibridge.digital 209.182.233.252 default yes 4450 169 yes 2025-06-21
vessella.ibridge.digital 209.182.233.252 default yes 6591 203 yes 2025-10-26
elevate.ibridge.digital 209.182.233.252 default yes 301 9 no 2026-06-12
hrm.ibridge.digital 209.182.233.252 default yes 875 25622 no 2026-06-29
dev.ibridge.digital 209.182.233.252 default yes 684 14 no 2026-07-08`

	domains := parseWebDomainsOutput([]byte(sampleOutput))
	assert.Len(t, domains, 11)

	assert.Equal(t, "payment.ibridge.digital", domains[0].Domain)
	assert.Equal(t, "209.182.233.252", domains[0].IP)
	assert.Equal(t, "default", domains[0].Template)
	assert.Equal(t, "yes", domains[0].SSL)
	assert.Equal(t, int64(357), domains[0].DiskUsageMB)
	assert.Equal(t, int64(10), domains[0].BandwidthMB)
	assert.False(t, domains[0].IsSuspended)
	assert.Equal(t, "2025-02-26", domains[0].DateCreated)

	assert.Equal(t, "signage.ibridge.digital", domains[2].Domain)
	assert.True(t, domains[2].IsSuspended)
	assert.Equal(t, int64(847), domains[2].DiskUsageMB)
	assert.Equal(t, int64(109), domains[2].BandwidthMB)
}

func TestParseUserOutputText(t *testing.T) {
	sampleUserOutput := `USERNAME: ibridge
FULL NAME: ibridgedigital
EMAIL: srujan@ibridge.digital
LANGUAGE: en
THEME: dark
SUSPENDED: no
PACKAGE: backupdefault
SHELL: bash
WEB DOMAINS: 11/unlimited
WEB ALIASES: 10/unlimited
DNS DOMAINS: 15/unlimited
DNS RECORDS: 208/unlimited
MAIL DOMAINS: 6/unlimited
MAIL ACCOUNTS: 0/unlimited
BACKUPS: 1/1
DATABASES: 40/unlimited
CRON_JOBS: 1/unlimited
DISK: 36835/unlimited
BANDWIDTH: 32497/unlimited
IP ADDRESSES: 1/0
TIME: 10:03:28
DATE: 2022-08-28`

	userMap := parseUserOutput([]byte(sampleUserOutput))
	assert.Equal(t, "ibridge", userMap["USERNAME"])
	assert.Equal(t, "ibridgedigital", userMap["FULL NAME"])
	assert.Equal(t, "srujan@ibridge.digital", userMap["EMAIL"])
	assert.Equal(t, "backupdefault", userMap["PACKAGE"])

	col := &defaultCollector{}
	user := &models.HostingUserCandidate{
		Username: "ibridge",
	}
	col.applyUserConfMap(user, userMap)

	assert.Equal(t, "ibridgedigital", user.FullName)
	assert.Equal(t, "srujan@ibridge.digital", user.Email)
	assert.Equal(t, "backupdefault", user.Package)
	assert.Equal(t, "11/unlimited", user.WebDomainsQuota)
	assert.Equal(t, 11, user.WebCount)
	assert.Equal(t, "15/unlimited", user.DNSDomainsQuota)
	assert.Equal(t, 15, user.DNSCount)
	assert.Equal(t, "36835/unlimited", user.DiskQuota)
	assert.Equal(t, int64(36835), user.DiskUsageMB)
	assert.Equal(t, "32497/unlimited", user.BandwidthQuota)
	assert.Equal(t, int64(32497), user.BandwidthMB)
	assert.Equal(t, "1/0", user.IPAddressesQuota)
	assert.Equal(t, "2022-08-28", user.DateCreated)
	assert.Equal(t, "10:03:28", user.TimeCreated)
}
