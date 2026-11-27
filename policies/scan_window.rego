package eol.window

import rego.v1

default allow := false
default reason := "denied: scan outside UTC window without grace extension"

# Active audit or incident grace period permits off-window collection for approved roles.
grace_active if {
	input.grace_extension.enabled == true
	count(input.grace_extension.reference_id) >= 5
	input.grace_extension.extra_minutes <= 15
	input.role in {"platform-ops", "compliance-lead"}
}

allow if {
	grace_active
}

allow if {
	not grace_active
	input.role in {"platform-ops", "compliance-lead", "cron-runner"}
	input.utc_hour >= 3
	input.utc_hour <= 23
}

reason := "allowed via active 15m grace period extension" if {
	allow
	grace_active
}

reason := "allowed within UTC scan window" if {
	allow
	not grace_active
}
