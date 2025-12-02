# Role-based Access Control (RBAC)
# --------------------------------
#
# This example defines an RBAC model for a Pet Store API. The Pet Store API allows
# users to look at pets, adopt them, update their stats, and so on. The policy
# controls which users can perform actions on which resources. The policy implements
# a classic Role-based Access Control model where users are assigned to roles and
# roles are granted the ability to perform some action(s) on some type of resource.
#
# This example shows how to:
#
#	* Define an RBAC model in Rego that interprets role mappings represented in JSON.
#	* Iterate/search across JSON data structures (e.g., role mappings)
#
# For more information see:
#
#	* Rego comparison to other systems: https://www.openpolicyagent.org/docs/latest/comparison-to-other-systems/
#	* Rego Iteration: https://www.openpolicyagent.org/docs/latest/#iteration

package transport.access

# import data.utils

# By default, deny requests
default allow = false

# Allow admins to do anything
allow {
	user_is_admin
}

# Allow the action if the user is granted permission to perform the action.
allow {
	some i

	role := input.user_role[i]
	perspective := input.entity_perspective
	perspective_allowed(role, perspective)
}


perspective_allowed(role, perspective) {
  allowed := data.perspective_rules[input.org_id][role].allowed_perspectives
  perspective == allowed[_]
}


# user_is_admin is true if...
user_is_admin {
	# for some `i`...
	some i

	# "admin" is the `i`-th element in the user->role mappings for the identified user.
	input.user_role[i] == "admin"
}
