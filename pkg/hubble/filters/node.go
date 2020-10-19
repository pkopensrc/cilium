package filters

import (
	"fmt"
	"regexp"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

// A NodeFilter filters on node name. An empty NodeFilter matches all nodes.
//
// NodeFilters are different to other filters as they are applied at the node
// level, not at the individual flow level.
type NodeFilter struct {
	whitelistRegexp *regexp.Regexp
	blacklistRegexp *regexp.Regexp
}

// NewNodeFilter returns a new NodeFilter with whitelist and blacklist.
func NewNodeFilter(whitelist, blacklist []*flowpb.FlowFilter) (*NodeFilter, error) {
	whitelistRegexp, err := nodeNamePatternsRegexp(whitelist)
	if err != nil {
		return nil, err
	}
	blacklistRegexp, err := nodeNamePatternsRegexp(blacklist)
	if err != nil {
		return nil, err
	}

	// short path: if there are no filters then return nil to avoid an
	// allocation
	if whitelistRegexp == nil && blacklistRegexp == nil {
		return nil, nil
	}

	return &NodeFilter{
		whitelistRegexp: whitelistRegexp,
		blacklistRegexp: blacklistRegexp,
	}, nil
}

// Match returns true if f matches nodeName.
func (f *NodeFilter) Match(nodeName string) bool {
	if f == nil {
		return true
	}
	if f.whitelistRegexp != nil && !f.whitelistRegexp.MatchString(nodeName) {
		return false
	}
	if f.blacklistRegexp != nil && f.blacklistRegexp.MatchString(nodeName) {
		return false
	}
	return true
}

// nodeNamePatternsRegexp returns the regular expression equivalent to the node
// patterns in flowFilters. If flowFilters contains no node patterns then it
// returns nil.
func nodeNamePatternsRegexp(flowFilters []*flowpb.FlowFilter) (*regexp.Regexp, error) {
	sb := &strings.Builder{}
	sb.WriteString(`\A(`)
	n := 0
	for _, flowFilter := range flowFilters {
		for _, nodePattern := range flowFilter.GetNodeNames() {
			n++
			if n > 1 {
				sb.WriteByte('|')
			}
			if err := appendNodeNamePatternRegexp(sb, nodePattern); err != nil {
				return nil, err
			}
		}
	}
	if n == 0 {
		return nil, nil
	}
	sb.WriteString(`)\z`)
	return regexp.Compile(sb.String())
}

// appendNodeNamePatternRegexp appends the regular expression equivalent to
// nodePattern to sb.
func appendNodeNamePatternRegexp(sb *strings.Builder, nodeNamePattern string) error {
	for _, r := range nodeNamePattern {
		switch {
		case r == '.':
			sb.WriteString(`\.`)
		case r == '*':
			sb.WriteString(`[\-0-9a-z]*`)
		case r == '-':
			fallthrough
		case r == '/':
			fallthrough
		case '0' <= r && r <= '9':
			fallthrough
		case 'a' <= r && r <= 'z':
			sb.WriteRune(r)
		default:
			return fmt.Errorf("%q: invalid rune in node name pattern", r)
		}
	}
	return nil
}
