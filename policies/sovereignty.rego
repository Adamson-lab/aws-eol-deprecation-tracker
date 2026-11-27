package eol.sovereignty

import rego.v1

default allow := false
default reason := "denied: region outside approved residency boundary"

approved_regions := {
	"fedramp-high": {"us-east-1", "us-west-2"},
	"eu-sovereign": {"eu-central-1", "eu-west-1"},
	"general": {"us-east-1", "us-west-2", "eu-central-1", "ap-southeast-1"},
}

allow if {
	input.region in approved_regions[input.residency]
}

reason := "allowed: region approved for residency boundary" if {
	allow
}
