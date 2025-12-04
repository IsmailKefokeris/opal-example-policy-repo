# Roles-based Access Control (RBAC)
# --------------------------------
#
#
# This example shows how to:
#
#	* Define an RBAC model in Rego that interprets roles mappings represented in JSON.
#	* Iterate/search across JSON data structures (e.g., roles mappings)
#
# For more information see:
#
#	* Rego comparison to other systems: https://www.openpolicyagent.org/docs/latest/comparison-to-other-systems/
#	* Rego Iteration: https://www.openpolicyagent.org/docs/latest/#iteration


package transport.access

default allow := false

# Allow the action if any of the user's org/role pairs permits the requested perspective.
allow if {
    some org_index, role_index

    org := input.user.Organisations[org_index]
    role := org.Roles[role_index].Id
    perspective := input.entity_perspective

    perspective_allowed(org.OrganisationId, role, perspective)
}

# Helper function: bind all variables locally and check membership.
perspective_allowed(org_id, role, perspective) if {
    allowed := data.perspective_rules[org_id][role].allowed_perspectives
    perspective == allowed[_]
}
