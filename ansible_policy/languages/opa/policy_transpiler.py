from dataclasses import dataclass, field
import traceback
import yaml
import argparse
import os
import glob
import re
import string
from typing import List, Union


from ansible_policy.models import Policy, PolicyMetadata
from ansible_policy.policybook.policybook_models import Policybook, PolicySet
from ansible_policy.policybook.policy_parser import VALID_ACTIONS
from ansible_policy.utils import init_logger
from ansible_policy.interfaces.policy_transpiler import PolicyTranspiler


from ansible_policy.languages.opa.rego_model import RegoPolicy, RegoFunc
from ansible_policy.languages.opa.expression_transpiler import ExpressionTranspiler


logger = init_logger(__name__, os.getenv("ANSIBLE_GK_LOG_LEVEL", "info"))

et = ExpressionTranspiler()

action_func_template = string.Template(
    """
${func_name} = true if {
    ${steps}
} else = false
"""
)


@dataclass
class OPATranspiler(PolicyTranspiler):
    def run(self, policybook: Policybook) -> List[Policy]:
        return self.policybook_to_rego(policybook)

    def policybook_to_rego(self, policybook: Policybook) -> List[Policy]:
        return self.policyset_to_rego(policybook.policy)

    def policyset_to_rego(self, policy_set: PolicySet) -> List[Policy]:
        if "PolicySet" not in policy_set:
            raise ValueError("no policy found")

        ps = policy_set["PolicySet"]
        if "name" not in ps:
            raise ValueError("name field is empty")

        policies = []
        for p in ps.get("policies", []):
            pol = p.get("Policy", {})

            rego_policy = RegoPolicy()
            # package
            _package = pol["name"]
            _package = self.clean_error_token(pol["name"])
            rego_policy.package = _package
            # import statements
            rego_policy.import_statements = [
                "import future.keywords.if",
                "import future.keywords.in",
            ]
            # tags
            rego_policy.tags = pol.get("tags", [])
            # vars
            rego_policy.vars_declaration = ps.get("vars", [])
            # target
            rego_policy.target = pol.get("target")

            # condition -> rule
            _name = self.clean_error_token(pol["name"])
            condition = pol.get("condition", {})
            root_func, condition_funcs, used_funcs = self.condition_to_rule(condition, _name)
            rego_policy.root_condition_func = root_func
            rego_policy.condition_funcs = condition_funcs
            rego_policy.util_funcs = used_funcs

            action = pol.get("actions", [])[0]
            action_func = self.action_to_rule(action, root_func)
            rego_policy.action_func = action_func
            rego_body = rego_policy.to_rego()

            policy = Policy(
                is_policybook=False,
                language="rego",
                metadata=PolicyMetadata(
                    target=rego_policy.target,
                    tags=rego_policy.tags,
                    attrs={"package": rego_policy.package},
                ),
                body=rego_body,
            )
            policies.append(policy)
        return policies

    def action_to_rule(self, input: dict, condition: RegoFunc):
        action = input["Action"]
        rules = []
        action_type = action.get("action", "")
        if action_type not in VALID_ACTIONS:
            raise ValueError(f"{action_type} is not supported. supported actions are {VALID_ACTIONS}")
        action_args = action.get("action_args", "")
        rules.append(condition.name)
        msg = action_args.get("msg", "")
        print_msg = self.make_rego_print(msg)
        rules.append(print_msg)
        template = action_func_template
        return self.make_func_from_cond(action_type, template, rules)

    # func to convert each condition to rego rules
    def condition_to_rule(self, condition: dict, policy_name: str):
        root_func, condition_funcs = et.trace_ast_tree(condition=condition, policy_name=policy_name)
        # util funcs
        used_funcs = []
        for func in condition_funcs:
            used_funcs.extend(func.util_funcs)
        used_funcs = list(set(used_funcs))
        return root_func, condition_funcs, used_funcs

    def make_rego_print(self, input_text):
        pattern = r"{{\s*([^}]+)\s*}}"
        replacement = r"%v"
        # replace vars part to rego style
        result = re.sub(pattern, replacement, input_text)
        vals = re.findall(pattern, input_text)
        if len(vals) != 0:
            # Strip whitespace from all string values in the list
            vals = [v.strip() if isinstance(v, str) else v for v in vals]
            val_str = ", ".join(vals)
            # replace " with '
            result = result.replace('"', "'")
            return f'print(sprintf("{result}", [{val_str}]))'
        else:
            return f'print("{input_text}")'

    def make_func_from_cond(self, name, template, conditions):
        _steps = self.join_with_separator(conditions, separator="\n    ")
        rego_block = template.safe_substitute(
            {
                "func_name": name,
                "steps": _steps,
            }
        )
        return rego_block

    def join_with_separator(self, str_or_list: str | list, separator: str = ", "):
        value = ""
        if isinstance(str_or_list, str):
            value = str_or_list
        elif isinstance(str_or_list, list):
            value = separator.join(str_or_list)
        return value

    def clean_error_token(self, in_str):
        return in_str.replace(" ", "_").replace("-", "_").replace("?", "").replace("(", "_").replace(")", "_")


def main():
    # import this only for main function
    from ansible_policy.config import Source

    parser = argparse.ArgumentParser(description="TODO")
    parser.add_argument("-i", "--input", help="")
    parser.add_argument("-o", "--output", help="")
    args = parser.parse_args()

    input_dir = args.input
    output_dir = args.output

    policy_name = "policy"
    source = Source(name=policy_name, source=input_dir, type="path")
    policies = source.install()

    transpiler = OPATranspiler()
    for policy in policies:
        if policy.is_policybook:
            policybook = policy.policybook_data
            print("policybook filepath:", policybook.filepath)
            rego_list = transpiler.run(policybook)
            for rego in rego_list:
                print("transpiled rego:", rego.body)


if __name__ == "__main__":
    main()
