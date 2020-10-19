// +build !privileged_tests

package filters

import (
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"

	"github.com/stretchr/testify/assert"
)

func TestNodeFilter(t *testing.T) {
	type test struct {
		name      string
		whitelist [][]string
		blacklist [][]string
		wantErr   bool
		want      map[string]bool
	}

	tests := []test{
		{
			name: "empty",
			want: map[string]bool{
				"runtime1": true,
			},
		},
		{
			name: "empty",
			want: map[string]bool{
				"runtime1": true,
			},
		},
		{
			name: "whitelist",
			whitelist: [][]string{
				{"runtime1"},
			},
			want: map[string]bool{
				"runtime1": true,
				"k8s1":     false,
			},
		},
		{
			name: "two_whitelists",
			whitelist: [][]string{
				{"runtime1"},
				{"k8s1"},
			},
			want: map[string]bool{
				"runtime1": true,
				"k8s1":     true,
				"k8s2":     false,
			},
		},
		{
			name: "whitelist_pattern",
			whitelist: [][]string{
				{"*s*"},
			},
			want: map[string]bool{
				"runtime1": false,
				"k8s1":     true,
				"k8s2":     true,
			},
		},
		{
			name: "blacklist",
			blacklist: [][]string{
				{"runtime1"},
			},
			want: map[string]bool{
				"runtime1": false,
				"k8s1":     true,
			},
		},
		{
			name: "whitelist_and_blacklist",
			whitelist: [][]string{
				{"*"},
			},
			blacklist: [][]string{
				{"*1"},
			},
			want: map[string]bool{
				"runtime1": false,
				"k8s1":     false,
				"k8s2":     true,
			},
		},
		{
			name: "bad_whitelist_pattern",
			whitelist: [][]string{
				{"["},
			},
			wantErr: true,
			want: map[string]bool{
				"runtime1": false,
			},
		},
		{
			name: "bad_blacklist_pattern",
			blacklist: [][]string{
				{"["},
			},
			wantErr: true,
			want: map[string]bool{
				"runtime1": false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			whitelist := makeFlowFilters(tt.whitelist)
			blacklist := makeFlowFilters(tt.blacklist)
			nodeFilter, err := NewNodeFilter(whitelist, blacklist)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, nodeFilter)
				return
			}

			assert.NoError(t, err)
			for nodeName, want := range tt.want {
				assert.Equal(t, want, nodeFilter.Match(nodeName))
			}
		})
	}
}

func TestNodeNamePatternsRegexp(t *testing.T) {
	type test struct {
		name    string
		nodess  [][]string
		wantErr bool
		wantNil bool
		want    string
	}

	tests := []test{
		{
			name:    "empty1",
			wantNil: true,
		},
		{
			name:    "empty2",
			nodess:  [][]string{},
			wantNil: true,
		},
		{
			name: "empty3",
			nodess: [][]string{
				{},
			},
			wantNil: true,
		},
		{
			name: "literal",
			nodess: [][]string{
				{"runtime1"},
			},
			want: `\A(runtime1)\z`,
		},
		{
			name: "literals1",
			nodess: [][]string{
				{"runtime1", "test-cluster/k8s1"},
			},
			want: `\A(runtime1|test-cluster/k8s1)\z`,
		},
		{
			name: "literals2",
			nodess: [][]string{
				{"runtime1"},
				{"test-cluster/k8s1"},
			},
			want: `\A(runtime1|test-cluster/k8s1)\z`,
		},
		{
			name: "complex_pattern",
			nodess: [][]string{
				{"runtime1.domain.com"},
				{"test-cluster/k8s*"},
			},
			want: `\A(runtime1\.domain\.com|test-cluster/k8s[\-0-9a-z]*)\z`,
		},
		{
			name: "invalid_rune",
			nodess: [][]string{
				{"_"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nodeNamePatternsRegexp(makeFlowFilters(tt.nodess))
			switch {
			case tt.wantErr:
				assert.Error(t, err)
				assert.Nil(t, got)
			case tt.wantNil:
				assert.NoError(t, err)
				assert.Nil(t, got)
			default:
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got.String())
			}
		})
	}
}

// makeFlowFilters creates slice of flowpb.FlowFilters from a slice of string
// slices.
func makeFlowFilters(nodeNamess [][]string) []*flowpb.FlowFilter {
	flowFilters := make([]*flowpb.FlowFilter, 0, len(nodeNamess))
	for _, nodeNames := range nodeNamess {
		ff := &flowpb.FlowFilter{
			NodeNames: nodeNames,
		}
		flowFilters = append(flowFilters, ff)
	}
	return flowFilters
}
