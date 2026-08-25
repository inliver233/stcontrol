package store

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type DiscordGuildMembershipPolicy struct {
	Enabled     bool   `json:"enabled"`
	GuildID     string `json:"guild_id"`
	GuildName   string `json:"guild_name"`
	MinimumDays int    `json:"minimum_days"`
}

type RegistrationMethodPolicy struct {
	Enabled            bool                          `json:"enabled"`
	InvitationRequired bool                          `json:"invitation_required"`
	GuildMembership    *DiscordGuildMembershipPolicy `json:"guild_membership,omitempty"`
}

type RegistrationMethodPolicies map[string]RegistrationMethodPolicy

type nodeRegistrationPolicyScan struct {
	node *Node
}

func (scan nodeRegistrationPolicyScan) Scan(source any) error {
	if scan.node == nil {
		return fmt.Errorf("nil node registration policy destination")
	}
	var raw []byte
	switch value := source.(type) {
	case []byte:
		raw = value
	case string:
		raw = []byte(value)
	default:
		return fmt.Errorf("unsupported node registration policy source %T", source)
	}
	var decoded struct {
		State   string                     `json:"state"`
		Methods RegistrationMethodPolicies `json:"methods"`
	}
	if len(raw) > 0 && raw[0] == '{' {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return fmt.Errorf("decode node registration policy: %w", err)
		}
	} else {
		// sqlmock fixtures from the scalar-policy generation supply this column
		// as plain text. Production queries always return the JSON object above.
		decoded.State = string(raw)
	}
	if decoded.Methods == nil {
		decoded.Methods = RegistrationMethodPolicies{}
	}
	scan.node.RegistrationPolicyState = decoded.State
	scan.node.RegistrationMethods = decoded.Methods
	return nil
}

func (policies *RegistrationMethodPolicies) Scan(source any) error {
	if policies == nil {
		return fmt.Errorf("nil registration method policy destination")
	}
	var raw []byte
	switch value := source.(type) {
	case nil:
		*policies = RegistrationMethodPolicies{}
		return nil
	case []byte:
		raw = value
	case string:
		raw = []byte(value)
	default:
		return fmt.Errorf("unsupported registration method policy source %T", source)
	}
	if len(raw) == 0 {
		*policies = RegistrationMethodPolicies{}
		return nil
	}
	var decoded RegistrationMethodPolicies
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return fmt.Errorf("decode registration method policies: %w", err)
	}
	if decoded == nil {
		decoded = RegistrationMethodPolicies{}
	}
	*policies = decoded
	return nil
}

func (policies RegistrationMethodPolicies) Value() (driver.Value, error) {
	if policies == nil {
		policies = RegistrationMethodPolicies{}
	}
	encoded, err := json.Marshal(policies)
	if err != nil {
		return nil, fmt.Errorf("encode registration method policies: %w", err)
	}
	return string(encoded), nil
}
