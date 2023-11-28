package sample_ansible_policy

import future.keywords.if
import future.keywords.in
import data.ansible_gatekeeper.resolve_var

_allowed_databases = ["allowed-db-1", "allowed-db-2"]
_target_module = "community.mongodb.mongodb_user"

find_not_allowed_db(task) := database {
    fqcn := task.module_fqcn
    fqcn == _target_module
    database := resolve_var(task.module_options.database, input.variables)
    not database in _allowed_databases
}

not_allowed_databases := found {
    found := [
        find_not_allowed_db(task) | task := input.playbooks[_].tasks[_]; find_not_allowed_db(task)
    ]
}

using_forbidden_database = true if {
    found := not_allowed_databases
    count(found) > 0
} else = false
