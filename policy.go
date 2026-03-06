package main

import (
	"fmt"
	"strings"
	"time"
)

// PolicyRule defines a rule from the config policy section.
// Whether it's a deny or allow rule is determined by which list it appears in.
type PolicyRule struct {
	Domain     string   `yaml:"domain,omitempty" json:"domain,omitempty"`
	PathPrefix string   `yaml:"path_prefix,omitempty" json:"path_prefix,omitempty"`
	URL        string   `yaml:"url,omitempty" json:"url,omitempty"`
	Method     string   `yaml:"method,omitempty" json:"method,omitempty"`
	Methods    []string `yaml:"methods,omitempty" json:"methods,omitempty"`
	Expires    string   `yaml:"expires,omitempty" json:"expires,omitempty"`
	OneShot    bool     `yaml:"one_shot,omitempty" json:"one_shot,omitempty"`
}

// DenyList holds deny rules that take absolute priority over grants.
type DenyList struct {
	rules []PolicyRule
}

// NewDenyList creates a DenyList directly from deny rules.
func NewDenyList(rules []PolicyRule) *DenyList {
	return &DenyList{rules: rules}
}

// IsDenied checks if a domain+path combination is denied.
func (d *DenyList) IsDenied(domain, path string) (bool, *PolicyRule) {
	return d.IsDeniedMethod(domain, path, "")
}

// IsDeniedMethod checks if a domain+path+method combination is denied.
func (d *DenyList) IsDeniedMethod(domain, path, method string) (bool, *PolicyRule) {
	for i := range d.rules {
		r := &d.rules[i]
		if !matchesDomain(r.Domain, domain) {
			continue
		}
		if r.PathPrefix != "" && !matchesPathPrefix(r.PathPrefix, path) {
			continue
		}
		if len(r.Methods) > 0 && method != "" {
			found := false
			for _, m := range r.Methods {
				if strings.EqualFold(m, method) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if r.Method != "" && method != "" && !strings.EqualFold(r.Method, method) {
			continue
		}
		return true, r
	}
	return false, nil
}

// ConvertPolicyRulesToGrants converts policy allow rules to Grant objects.
func ConvertPolicyRulesToGrants(rules []PolicyRule) []*Grant {
	now := time.Now().Add(-10 * time.Second) // GrantedAt defaults to now-10s
	var grants []*Grant
	for i, r := range rules {
		base := Grant{
			Source:    "policy",
			OneShot:   r.OneShot,
			GrantedAt: now,
		}

		switch {
		case r.URL != "":
			base.Type = GrantTypeLiteral
			base.URL = r.URL
		case r.PathPrefix != "":
			base.Type = GrantTypePathPrefix
			base.Domain = r.Domain
			base.PathPrefix = r.PathPrefix
		default:
			base.Type = GrantTypeDomain
			base.Domain = r.Domain
		}

		if r.Expires != "" {
			dur, err := time.ParseDuration(r.Expires)
			if err == nil {
				base.Duration = dur
				base.ExpiresAt = now.Add(dur)
			}
		}

		methods := r.Methods
		if len(methods) == 0 && r.Method != "" {
			methods = []string{r.Method}
		}

		if len(methods) == 0 {
			base.ID = fmt.Sprintf("policy-%d", i)
			grant := base
			grants = append(grants, &grant)
		} else {
			for j, m := range methods {
				grant := base
				grant.ID = fmt.Sprintf("policy-%d-%d", i, j)
				grant.Method = m
				grants = append(grants, &grant)
			}
		}
	}
	return grants
}
