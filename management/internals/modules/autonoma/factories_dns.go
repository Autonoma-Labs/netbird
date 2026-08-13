package autonoma

import (
	"fmt"

	"github.com/autonoma-ai/sdk/sdks/go/autonoma"

	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
)

// ZoneInput creates a private DNS zone.
type ZoneInput struct {
	AccountID string `json:"accountId"`
	Name      string `json:"name"`
	// Domain is the zone's apex. It has to be a valid domain without wildcards.
	Domain             string   `json:"domain"`
	Enabled            bool     `json:"enabled"`
	EnableSearchDomain bool     `json:"enableSearchDomain,omitempty"`
	DistributionGroups []string `json:"distributionGroups"`
}

func (f *factories) zoneFactory(in *ZoneInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	created, err := f.deps.ZonesManager.CreateZone(f.ctx(), in.AccountID, owner, &zones.Zone{
		AccountID:          in.AccountID,
		Name:               in.Name,
		Domain:             in.Domain,
		Enabled:            in.Enabled,
		EnableSearchDomain: in.EnableSearchDomain,
		DistributionGroups: in.DistributionGroups,
	})
	if err != nil {
		return nil, fmt.Errorf("create zone %s: %w", in.Domain, err)
	}

	return map[string]any{
		"id":        created.ID,
		"accountId": in.AccountID,
		"domain":    created.Domain,
	}, nil
}

func (f *factories) zoneTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.ZonesManager.DeleteZone(f.ctx(), accountID, owner, recordString(record, "id")))
}

// RecordInput adds a resource record to a zone.
type RecordInput struct {
	AccountID string `json:"accountId"`
	ZoneID    string `json:"zoneId"`
	Name      string `json:"name"`
	// Type is A, AAAA or CNAME.
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

func (f *factories) recordFactory(in *RecordInput, ctx autonoma.FactoryContext) (map[string]any, error) {
	owner, err := accountOwner(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}

	created, err := f.deps.RecordsManager.CreateRecord(f.ctx(), in.AccountID, owner, in.ZoneID, &records.Record{
		AccountID: in.AccountID,
		ZoneID:    in.ZoneID,
		Name:      in.Name,
		Type:      records.RecordType(in.Type),
		Content:   in.Content,
		TTL:       in.TTL,
	})
	if err != nil {
		return nil, fmt.Errorf("create dns record %s: %w", in.Name, err)
	}

	return map[string]any{
		"id":        created.ID,
		"accountId": in.AccountID,
		"zoneId":    in.ZoneID,
		"name":      created.Name,
	}, nil
}

func (f *factories) recordTeardown(record map[string]any, ctx autonoma.FactoryContext) error {
	accountID := recordString(record, "accountId")
	owner, err := accountOwner(ctx, accountID)
	if err != nil {
		return err
	}
	return ignoreNotFound(f.deps.RecordsManager.DeleteRecord(f.ctx(), accountID, owner,
		recordString(record, "zoneId"), recordString(record, "id")))
}
