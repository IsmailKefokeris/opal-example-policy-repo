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

# By default, deny requests
default allow = false

# Allow the action if the user is granted permission to perform the action.
allow {
	some org_index, role_index

    org := input.user.Organisations[org_index]
    role := org.Roles[role_index].Id
    perspective := input.entity_perspective

    perspective_allowed(org.OrganisationId, role, perspective)

}


perspective_allowed(roles, perspective) {
	some idx
# Gets all Perspectives that this current org, with roles can see.
	allowed := data.perspective_rules[org_id][role].allowed_perspectives
# Iterate through each and check whether that is the perspective that was requested.
	perspective == allowed[idx]
}
