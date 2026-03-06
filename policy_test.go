package main

import (
	"testing"
	"time"
)

func TestConvertDomainRule(t *testing.T) {
	rules := []PolicyRule{{Domain: "httpbin.org"}}
	grants := ConvertPolicyRulesToGrants(rules)
	if len(grants) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(grants))
	}
	g := grants[0]
	if g.Type != GrantTypeDomain {
		t.Fatalf("expected domain type, got %s", g.Type)
	}
	if g.Domain != "httpbin.org" {
		t.Fatalf("expected httpbin.org, got %s", g.Domain)
	}
	if g.Source != "policy" {
		t.Fatalf("expected source=policy, got %s", g.Source)
	}
	if g.GrantedAt.IsZero() {
		t.Fatal("expected non-zero GrantedAt")
	}
}

func TestConvertDomainWithPathPrefix(t *testing.T) {
	rules := []PolicyRule{{Domain: "api.stripe.com", PathPrefix: "/v1/charges"}}
	grants := ConvertPolicyRulesToGrants(rules)
	if len(grants) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(grants))
	}
	if grants[0].Type != GrantTypePathPrefix {
		t.Fatalf("expected path_prefix type, got %s", grants[0].Type)
	}
	if grants[0].PathPrefix != "/v1/charges" {
		t.Fatalf("expected /v1/charges, got %s", grants[0].PathPrefix)
	}
}

func TestConvertURLRule(t *testing.T) {
	rules := []PolicyRule{{URL: "https://api.stripe.com/v1/charges"}}
	grants := ConvertPolicyRulesToGrants(rules)
	if len(grants) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(grants))
	}
	if grants[0].Type != GrantTypeLiteral {
		t.Fatalf("expected literal type, got %s", grants[0].Type)
	}
}

func TestConvertOneShotAndExpiry(t *testing.T) {
	rules := []PolicyRule{{Domain: "oneshot.com", OneShot: true, Expires: "1h"}}
	grants := ConvertPolicyRulesToGrants(rules)
	g := grants[0]
	if !g.OneShot {
		t.Fatal("expected one_shot=true")
	}
	if g.ExpiresAt.IsZero() {
		t.Fatal("expected non-zero expiry")
	}
	if g.Duration != 1*time.Hour {
		t.Fatalf("expected 1h duration, got %v", g.Duration)
	}
	if time.Until(g.ExpiresAt) < 59*time.Minute {
		t.Fatal("expected expiry ~1h from now")
	}
}

func TestConvertMethodRestriction(t *testing.T) {
	rules := []PolicyRule{{Domain: "api.example.com", Methods: []string{"GET", "POST"}}}
	grants := ConvertPolicyRulesToGrants(rules)
	if len(grants) != 2 {
		t.Fatalf("expected 2 grants (one per method), got %d", len(grants))
	}
	methods := map[string]bool{}
	for _, g := range grants {
		methods[g.Method] = true
	}
	if !methods["GET"] || !methods["POST"] {
		t.Fatalf("expected GET and POST methods, got %v", methods)
	}
}

func TestConvertSingleMethodField(t *testing.T) {
	rules := []PolicyRule{{Domain: "api.example.com", Method: "DELETE"}}
	grants := ConvertPolicyRulesToGrants(rules)
	if len(grants) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(grants))
	}
	if grants[0].Method != "DELETE" {
		t.Fatalf("expected DELETE, got %s", grants[0].Method)
	}
}

func TestDenyBeforeAllow(t *testing.T) {
	deny := NewDenyList([]PolicyRule{{Domain: "*.evil.com"}})

	denied, rule := deny.IsDenied("api.evil.com", "/foo")
	if !denied {
		t.Fatal("expected api.evil.com to be denied")
	}
	if rule == nil {
		t.Fatal("expected deny rule to be returned")
	}

	denied, _ = deny.IsDenied("api.good.com", "/foo")
	if denied {
		t.Fatal("expected api.good.com to not be denied")
	}
}

func TestDenyExactDomain(t *testing.T) {
	deny := NewDenyList([]PolicyRule{{Domain: "bad.com"}})

	denied, _ := deny.IsDenied("bad.com", "/")
	if !denied {
		t.Fatal("expected bad.com to be denied")
	}

	denied, _ = deny.IsDenied("notbad.com", "/")
	if denied {
		t.Fatal("expected notbad.com to not be denied")
	}
}

func TestDenyWithPathPrefix(t *testing.T) {
	deny := NewDenyList([]PolicyRule{{Domain: "api.example.com", PathPrefix: "/admin"}})

	denied, _ := deny.IsDenied("api.example.com", "/admin/users")
	if !denied {
		t.Fatal("expected /admin/users to be denied")
	}

	denied, _ = deny.IsDenied("api.example.com", "/api/users")
	if denied {
		t.Fatal("expected /api/users to not be denied")
	}
}

func TestConvertRulesSource(t *testing.T) {
	rules := []PolicyRule{{Domain: "a.com"}}
	grants := ConvertPolicyRulesToGrants(rules)
	if grants[0].Source != "policy" {
		t.Fatalf("expected source=policy, got %s", grants[0].Source)
	}
}

func TestDenyMethodRestriction(t *testing.T) {
	deny := NewDenyList([]PolicyRule{{Domain: "api.example.com", Methods: []string{"DELETE"}}})

	denied, _ := deny.IsDeniedMethod("api.example.com", "/resource", "DELETE")
	if !denied {
		t.Fatal("expected DELETE to be denied")
	}

	denied, _ = deny.IsDeniedMethod("api.example.com", "/resource", "GET")
	if denied {
		t.Fatal("expected GET to not be denied")
	}
}
