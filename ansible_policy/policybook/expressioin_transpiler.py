#!/usr/bin/env python3

#  Copyright 2022 Red Hat, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import json
import string
from ansible_policy.policybook.rego_model import RegoFunc

# rego util funcs
item_not_in_list_func = """
check_item_not_in_list(lhs_list, rhs_list) = true if {
    array := [item | item := lhs_list[_]; item in rhs_list]
    count(array) == 0
} else = false
"""

item_in_list_func = """
check_item_in_list(lhs_list, rhs_list) = true if {
    array := [item | item := lhs_list[_]; item in rhs_list]
    count(array) > 0
} else = false
"""
item_key_not_in_list_func = """
check_item_key_not_in_list(lhs_list, rhs_list, key) = true if {
    array := [item | item := lhs_list[_]; object.get(item, key, "none") in rhs_list]
    count(array) == 0
} else = false
"""

item_key_in_list_func = """
check_item_key_in_list(lhs_list, rhs_list, key) = true if {
    array := [item | item := lhs_list[_]; object.get(item, key, "none") in rhs_list]
    count(array) > 0
} else = false
"""

to_list_func = """
to_list(val) = output if {
    is_array(val)
    output = val
}

to_list(val) = output if {
    not is_array(val)
    output = [val]
}
"""

if_func = string.Template(
    """
${func_name} = true if {
    ${steps}
}
"""
)


class BaseExpression:
    util_funcs = []

    def match(self, ast_exp, expression_type):
        return expression_type in ast_exp

    def change_data_format(self, data):
        if isinstance(data, list):
            return json.dumps([self.change_data_format(item) for item in data])
        elif isinstance(data, dict) and "String" in data:
            return f'"{data["String"]}"'
        elif isinstance(data, dict) and "Input" in data:
            return data["Input"]
        elif isinstance(data, dict) and "Variable" in data:
            return data["Variable"]
        elif isinstance(data, dict) and "Boolean" in data:
            return data["Boolean"]
        elif isinstance(data, dict) and "Integer" in data:
            return data["Integer"]
        elif isinstance(data, dict) and "Float" in data:
            return data["Float"]
        elif isinstance(data, dict) and "NullType" in data:
            return "null"
        else:
            return data

    def make_rego(self, name, condition):
        rego_block = if_func.safe_substitute(
            {
                "func_name": name,
                "steps": condition,
            }
        )
        return rego_block


class AndAllExpression(BaseExpression):
    def match(self, ast_exp):
        return super().match(ast_exp, "AndExpression") or super().match(ast_exp, "AllCondition")

    def make_rego(self, name, conditions):
        _steps = join_with_separator(conditions, separator="\n    ")
        return super().make_rego(name, _steps)


class OrAnyExpression(BaseExpression):
    def match(self, ast_exp):
        return super().match(ast_exp, "OrExpression") or super().match(ast_exp, "AnyCondition")

    def make_rego(self, name, conditions):
        rego_blocks = ""
        for cond in conditions:
            rego_blocks = rego_blocks + super().make_rego(name, cond)
        return rego_blocks


class NotAllExpression(BaseExpression):
    def match(self, ast_exp):
        return super().match(ast_exp, "NotAllCondition")

    def make_rego(self, name, conditions):
        rego_blocks = ""
        for cond in conditions:
            rego_blocks = rego_blocks + super().make_rego(name, "not " + cond)
        return rego_blocks


class EqualsExpression(BaseExpression):
    def match(self, ast_exp):
        return super().match(ast_exp, "EqualsExpression")

    def make_rego_exp(self, ast_exp):
        lhs = ast_exp["EqualsExpression"]["lhs"]
        lhs_val = self.change_data_format(lhs)
        rhs = ast_exp["EqualsExpression"]["rhs"]
        for type, val in rhs.items():
            if type == "Boolean":
                if val:
                    return f"{lhs_val}"
                else:
                    return f"not {lhs_val}"
            else:
                rhs_val = self.change_data_format(rhs)
                return f"{lhs_val} == {rhs_val}"

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


class NotEqualsExpression(BaseExpression):
    def match(self, ast_exp):
        return super().match(ast_exp, "NotEqualsExpression")

    def make_rego_exp(self, ast_exp):
        lhs = ast_exp["NotEqualsExpression"]["lhs"]
        lhs_val = self.change_data_format(lhs)
        rhs = ast_exp["NotEqualsExpression"]["rhs"]
        for type, val in rhs.items():
            if type == "Boolean":
                if val:
                    return f"not {lhs_val}"
                else:
                    return f"{lhs_val}"
            else:
                rhs_val = self.change_data_format(rhs)
                return f"{lhs_val} != {rhs_val}"

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


class ItemInListExpression(BaseExpression):
    template = string.Template(
        """lhs_list = to_list(${lhs})
    check_item_in_list(lhs_list, ${rhs})"""
    )
    util_funcs = [to_list_func, item_in_list_func]

    def match(self, ast_exp):
        if "ItemInListExpression" in ast_exp:
            return True
        else:
            return False

    def make_rego_exp(self, ast_exp):
        lhs = ast_exp["ItemInListExpression"]["lhs"]
        lhs_val = self.change_data_format(lhs)
        rhs = ast_exp["ItemInListExpression"]["rhs"]
        rhs_val = self.change_data_format(rhs)
        return self.template.safe_substitute({"lhs": lhs_val, "rhs": rhs_val})

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


class ItemNotInListExpression(BaseExpression):
    template = string.Template(
        """lhs_list = to_list(${lhs})
    check_item_not_in_list(lhs_list, ${rhs})"""
    )
    util_funcs = [to_list_func, item_not_in_list_func]

    def match(self, ast_exp):
        if "ItemNotInListExpression" in ast_exp:
            return True
        else:
            return False

    def make_rego_exp(self, ast_exp):
        lhs = ast_exp["ItemNotInListExpression"]["lhs"]
        lhs_val = self.change_data_format(lhs)
        rhs = ast_exp["ItemNotInListExpression"]["rhs"]
        rhs_val = self.change_data_format(rhs)
        return self.template.safe_substitute({"lhs": lhs_val, "rhs": rhs_val})

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


class ListContainsItemExpression(BaseExpression):
    template = string.Template(
        """lhs_list = to_list(${lhs})
    check_item_in_list(lhs_list, ${rhs})"""
    )
    util_funcs = [to_list_func, item_in_list_func]

    def match(self, ast_exp):
        if "ListContainsItemExpression" in ast_exp:
            return True
        else:
            return False

    def make_rego_exp(self, ast_exp):
        lhs = ast_exp["ListContainsItemExpression"]["lhs"]
        lhs_val = self.change_data_format(lhs)
        rhs = ast_exp["ListContainsItemExpression"]["rhs"]
        rhs_val = self.change_data_format(rhs)
        return self.template.safe_substitute({"lhs": rhs_val, "rhs": lhs_val})

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


class ListNotContainsItemExpression(BaseExpression):
    template = string.Template(
        """lhs_list = to_list(${lhs})
    check_item_not_in_list(lhs_list, ${rhs})"""
    )
    util_funcs = [to_list_func, item_not_in_list_func]

    def match(self, ast_exp):
        if "ListNotContainsItemExpression" in ast_exp:
            return True
        else:
            return False

    def make_rego_exp(self, ast_exp):
        lhs = ast_exp["ListNotContainsItemExpression"]["lhs"]
        lhs_val = self.change_data_format(lhs)
        rhs = ast_exp["ListNotContainsItemExpression"]["rhs"]
        rhs_val = self.change_data_format(rhs)
        return self.template.safe_substitute({"lhs": rhs_val, "rhs": lhs_val})

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


class KeyInDictExpression(BaseExpression):
    template = string.Template(
        """${lhs}
    input_keys := [key | ${lhs}[key]; key == ${rhs}]
    count(input_keys) > 0"""
    )
    util_funcs = [to_list_func, item_not_in_list_func]

    def match(self, ast_exp):
        if "KeyInDictExpression" in ast_exp:
            return True
        else:
            return False

    def make_rego_exp(self, ast_exp):
        lhs = ast_exp["KeyInDictExpression"]["lhs"]
        lhs_val = self.change_data_format(lhs)
        rhs = ast_exp["KeyInDictExpression"]["rhs"]
        rhs_val = self.change_data_format(rhs)
        return self.template.safe_substitute({"lhs": lhs_val, "rhs": rhs_val})

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


class KeyNotInDictExpression(BaseExpression):
    template = string.Template(
        """${lhs}
    input_keys := [key | ${lhs}[key]; key == ${rhs}]
    count(input_keys) == 0"""
    )
    util_funcs = [to_list_func, item_not_in_list_func]

    def match(self, ast_exp):
        if "KeyNotInDictExpression" in ast_exp:
            return True
        else:
            return False

    def make_rego_exp(self, ast_exp):
        lhs = ast_exp["KeyNotInDictExpression"]["lhs"]
        lhs_val = self.change_data_format(lhs)
        rhs = ast_exp["KeyNotInDictExpression"]["rhs"]
        rhs_val = self.change_data_format(rhs)
        return self.template.safe_substitute({"lhs": lhs_val, "rhs": rhs_val})

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


class IsNotDefinedExpression(BaseExpression):
    args_is_not_defined_template = string.Template(
        """${val1}
    not ${val2}"""
    )
    var_is_not_defined_template = string.Template("""not ${val1}""")
    util_funcs = [to_list_func, item_not_in_list_func]

    def match(self, ast_exp):
        if "IsNotDefinedExpression" in ast_exp:
            return True
        else:
            return False

    def make_rego_exp(self, ast_exp):
        val = self.change_data_format(ast_exp["IsNotDefinedExpression"])
        if "." in val:
            val_key = val.split(".")[-1]
            val_dict = val.replace(f".{val_key}", "")
            return self.args_is_not_defined_template.safe_substitute({"val1": val_dict, "val2": val})
        else:
            return self.var_is_not_defined_template.safe_substitute({"val1": val})

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


class IsDefinedExpression(BaseExpression):
    args_is_defined_template = string.Template(
        """${val1}
    ${val2}"""
    )
    var_is_defined_template = string.Template("""${val1}""")

    util_funcs = [to_list_func, item_not_in_list_func]

    def match(self, ast_exp):
        if "IsDefinedExpression" in ast_exp:
            return True
        else:
            return False

    def make_rego_exp(self, ast_exp):
        val = self.change_data_format(ast_exp["IsDefinedExpression"])
        if "." in val:
            val_key = val.split(".")[-1]
            val_dict = val.replace(f".{val_key}", "")
            return self.args_is_defined_template.safe_substitute({"val1": val_dict, "val2": val})
        else:
            return self.var_is_defined_template.safe_substitute({"val1": val})

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


class GreaterThanExpression(BaseExpression):
    def match(self, ast_exp):
        return super().match(ast_exp, "GreaterThanExpression")

    def make_rego_exp(self, ast_exp):
        lhs = ast_exp["GreaterThanExpression"]["lhs"]
        lhs_val = self.change_data_format(lhs)
        rhs = ast_exp["GreaterThanExpression"]["rhs"]
        rhs_val = self.change_data_format(rhs)
        return f"{lhs_val} > {rhs_val}"

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


class LessThanExpression(BaseExpression):
    def match(self, ast_exp):
        return super().match(ast_exp, "LessThanExpression")

    def make_rego_exp(self, ast_exp):
        lhs = ast_exp["LessThanExpression"]["lhs"]
        lhs_val = self.change_data_format(lhs)
        rhs = ast_exp["LessThanExpression"]["rhs"]
        rhs_val = self.change_data_format(rhs)
        return f"{lhs_val} < {rhs_val}"

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


class GreaterThanOrEqualToExpression(BaseExpression):
    def match(self, ast_exp):
        return super().match(ast_exp, "GreaterThanOrEqualToExpression")

    def make_rego_exp(self, ast_exp):
        lhs = ast_exp["GreaterThanOrEqualToExpression"]["lhs"]
        lhs_val = self.change_data_format(lhs)
        rhs = ast_exp["GreaterThanOrEqualToExpression"]["rhs"]
        rhs_val = self.change_data_format(rhs)
        return f"{lhs_val} >= {rhs_val}"

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


class LessThanOrEqualToExpression(BaseExpression):
    def match(self, ast_exp):
        return super().match(ast_exp, "LessThanOrEqualToExpression")

    def make_rego_exp(self, ast_exp):
        lhs = ast_exp["LessThanOrEqualToExpression"]["lhs"]
        lhs_val = self.change_data_format(lhs)
        rhs = ast_exp["LessThanOrEqualToExpression"]["rhs"]
        rhs_val = self.change_data_format(rhs)
        return f"{lhs_val} <= {rhs_val}"

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


class NegateExpression(BaseExpression):
    def match(self, ast_exp):
        return super().match(ast_exp, "NegateExpression")

    def make_rego_exp(self, ast_exp):
        val = self.change_data_format(ast_exp["NegateExpression"])
        return f"not {val}"

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


# TODO: handle regex (search and match)
class SearchMatchesExpression(BaseExpression):
    def match(self, ast_exp):
        return super().match(ast_exp, "SearchMatchesExpression")

    def make_rego_exp(self, ast_exp):
        lhs = ast_exp["SearchMatchesExpression"]["lhs"]
        lhs_val = self.change_data_format(lhs)
        rhs = ast_exp["SearchMatchesExpression"]["rhs"]["SearchType"]["pattern"]
        rhs_val = self.change_data_format(rhs)
        for option in ast_exp["SearchMatchesExpression"]["rhs"]["SearchType"]["options"]:
            if option["name"]["String"] == "ignorecase" and option["value"]["Boolean"]:
                lhs_val = f"lower({lhs_val})"
                rhs_val = f"lower({rhs_val})"
        if ast_exp["SearchMatchesExpression"]["rhs"]["SearchType"]["kind"]["String"] == "search":
            return f"contains({lhs_val}, {rhs_val})"
        elif ast_exp["SearchMatchesExpression"]["rhs"]["SearchType"]["kind"]["String"] == "match":
            return f"startswith({lhs_val}, {rhs_val})"
        elif ast_exp["SearchMatchesExpression"]["rhs"]["SearchType"]["kind"]["String"] == "regex":
            return f"regex.find_n({rhs_val}, {lhs_val}, 1) != []"

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


# TODO: handle regex (search and match)
class SearchNotMatchesExpression(BaseExpression):
    def match(self, ast_exp):
        return super().match(ast_exp, "SearchNotMatchesExpression")

    def make_rego_exp(self, ast_exp):
        lhs = ast_exp["SearchNotMatchesExpression"]["lhs"]
        lhs_val = self.change_data_format(lhs)
        rhs = ast_exp["SearchNotMatchesExpression"]["rhs"]["SearchType"]["pattern"]
        rhs_val = self.change_data_format(rhs)
        if ast_exp["SearchNotMatchesExpression"]["rhs"]["SearchType"]["kind"]["String"] == "search":
            return f"not contains({lhs_val}, {rhs_val})"
        elif ast_exp["SearchNotMatchesExpression"]["rhs"]["SearchType"]["kind"]["String"] == "match":
            return f"not startswith({lhs_val}, {rhs_val})"
        elif ast_exp["SearchNotMatchesExpression"]["rhs"]["SearchType"]["kind"]["String"] == "regex":
            return f"regex.find_n({rhs_val}, {lhs_val}, 1) == []"

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


# TODO: support various pattern
# now only support "search" and compare
class SelectExpression(BaseExpression):
    compare_in_list_template = string.Template(
        """array := [item | item := ${lhs}[_]; item ${operator} ${rhs}]
    count(array) > 0"""
    )
    template = string.Template(
        """rhs_list = to_list(${rhs})
    check_item_in_list(${lhs}, rhs_list)"""
    )
    # TODO: remove when type is not search
    util_funcs = [to_list_func, item_in_list_func]

    def match(self, ast_exp):
        return super().match(ast_exp, "SelectExpression")

    def make_rego_exp(self, ast_exp):
        lhs = ast_exp["SelectExpression"]["lhs"]
        lhs_val = self.change_data_format(lhs)
        rhs_operator_val = ast_exp["SelectExpression"]["rhs"]["operator"]["String"]
        rhs_value = ast_exp["SelectExpression"]["rhs"]["value"]
        rhs_value_val = self.change_data_format(rhs_value)
        if rhs_operator_val == "search" or rhs_operator_val == "==":
            return self.template.safe_substitute({"lhs": lhs_val, "rhs": rhs_value_val})
        elif rhs_operator_val == ">=" or rhs_operator_val == ">" or rhs_operator_val == "<=" or rhs_operator_val == "<":
            return self.compare_in_list_template.safe_substitute({"lhs": lhs_val, "rhs": rhs_value_val, "operator": rhs_operator_val})

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


# TODO: support various pattern (now only support "search" and compare)
class SelectNotExpression(BaseExpression):
    compare_not_in_list_template = string.Template(
        """array := [item | item := ${lhs}[_]; item ${operator} ${rhs}]
    count(array) == 0"""
    )
    template = string.Template(
        """rhs_list = to_list(${rhs})
    check_item_not_in_list(${lhs}, rhs_list)"""
    )
    # TODO: remove when type is not search
    util_funcs = [to_list_func, item_not_in_list_func]

    def match(self, ast_exp):
        return super().match(ast_exp, "SelectNotExpression")

    def make_rego_exp(self, ast_exp):
        lhs = ast_exp["SelectNotExpression"]["lhs"]
        lhs_val = self.change_data_format(lhs)
        rhs_operator_val = ast_exp["SelectNotExpression"]["rhs"]["operator"]["String"]
        rhs_value = ast_exp["SelectNotExpression"]["rhs"]["value"]
        rhs_value_val = self.change_data_format(rhs_value)
        if rhs_operator_val == "search" or rhs_operator_val == "==":
            return self.template.safe_substitute({"lhs": lhs_val, "rhs": rhs_value_val})
        elif rhs_operator_val == ">=" or rhs_operator_val == ">" or rhs_operator_val == "<=" or rhs_operator_val == "<":
            return self.compare_not_in_list_template.safe_substitute({"lhs": lhs_val, "rhs": rhs_value_val, "operator": rhs_operator_val})

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


class SelectAttrExpression(BaseExpression):
    compare_in_list_template = string.Template(
        """array := [item | item := ${lhs}[_]; object.get(item, ["${key}"], "none") ${operator} ${rhs}]
    count(array) > 0"""
    )
    template = string.Template(
        """rhs_list = to_list(${rhs})
    check_item_key_in_list(${lhs}, rhs_list, ["${key}"])"""
    )
    # TODO: remove when type is not search
    util_funcs = [to_list_func, item_key_in_list_func]

    def match(self, ast_exp):
        return super().match(ast_exp, "SelectAttrExpression")

    def make_rego_exp(self, ast_exp):
        lhs = ast_exp["SelectAttrExpression"]["lhs"]
        lhs_val = self.change_data_format(lhs)
        rhs_key_val = ast_exp["SelectAttrExpression"]["rhs"]["key"]["String"]
        rhs_operator_val = ast_exp["SelectAttrExpression"]["rhs"]["operator"]["String"]
        rhs_value = ast_exp["SelectAttrExpression"]["rhs"]["value"]
        rhs_value_val = self.change_data_format(rhs_value)
        if rhs_operator_val == "search" or rhs_operator_val == "==":
            return self.template.safe_substitute({"lhs": lhs_val, "rhs": rhs_value_val, "key": rhs_key_val})
        elif rhs_operator_val == ">=" or rhs_operator_val == ">" or rhs_operator_val == "<=" or rhs_operator_val == "<":
            return self.compare_in_list_template.safe_substitute(
                {
                    "lhs": lhs_val,
                    "rhs": rhs_value_val,
                    "key": rhs_key_val,
                    "operator": rhs_operator_val,
                }
            )

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


class SelectAttrNotExpression(BaseExpression):
    compare_not_in_list_template = string.Template(
        """array := [item | item := ${lhs}[_]; object.get(item, ["${key}"], "none") ${operator} ${rhs}]
    count(array) == 0"""
    )
    template = string.Template(
        """rhs_list = to_list(${rhs})
    check_item_key_not_in_list(${lhs}, rhs_list, ["${key}"])"""
    )
    # TODO: remove when type is not search
    util_funcs = [to_list_func, item_key_not_in_list_func]

    def match(self, ast_exp):
        return super().match(ast_exp, "SelectAttrNotExpression")

    def make_rego_exp(self, ast_exp):
        lhs = ast_exp["SelectAttrNotExpression"]["lhs"]
        lhs_val = self.change_data_format(lhs)
        rhs_key_val = ast_exp["SelectAttrNotExpression"]["rhs"]["key"]["String"]
        rhs_operator_val = ast_exp["SelectAttrNotExpression"]["rhs"]["operator"]["String"]
        rhs_value = ast_exp["SelectAttrNotExpression"]["rhs"]["value"]
        rhs_value_val = self.change_data_format(rhs_value)
        if rhs_operator_val == "search" or rhs_operator_val == "==":
            return self.template.safe_substitute({"lhs": lhs_val, "rhs": rhs_value_val, "key": rhs_key_val})
        elif rhs_operator_val == ">=" or rhs_operator_val == ">" or rhs_operator_val == "<=" or rhs_operator_val == "<":
            return self.compare_not_in_list_template.safe_substitute(
                {
                    "lhs": lhs_val,
                    "rhs": rhs_value_val,
                    "key": rhs_key_val,
                    "operator": rhs_operator_val,
                }
            )

    def make_rego(self, name, ast_exp):
        condition = self.make_rego_exp(ast_exp)
        return super().make_rego(name, condition)


class ExpressionTranspiler:
    AndAllExpression = AndAllExpression()
    OrAnyExpression = OrAnyExpression()
    NotAllExpression = NotAllExpression()
    EqualsExpression = EqualsExpression()
    NotEqualsExpression = NotEqualsExpression()
    ItemInListExpression = ItemInListExpression()
    ItemNotInListExpression = ItemNotInListExpression()
    ListContainsItemExpression = ListContainsItemExpression()
    ListNotContainsItemExpression = ListNotContainsItemExpression()
    KeyInDictExpression = KeyInDictExpression()
    KeyNotInDictExpression = KeyNotInDictExpression()
    IsDefinedExpression = IsDefinedExpression()
    IsNotDefinedExpression = IsNotDefinedExpression()
    LessThanExpression = LessThanExpression()
    LessThanOrEqualToExpression = LessThanOrEqualToExpression()
    GreaterThanExpression = GreaterThanExpression()
    GreaterThanOrEqualToExpression = GreaterThanOrEqualToExpression()
    NegateExpression = NegateExpression()
    SearchMatchesExpression = SearchMatchesExpression()
    SearchNotMatchesExpression = SearchNotMatchesExpression()
    SelectExpression = SelectExpression()
    SelectNotExpression = SelectNotExpression()
    SelectAttrExpression = SelectAttrExpression()
    SelectAttrNotExpression = SelectAttrNotExpression()
    simple_expressions = [
        EqualsExpression,
        NotEqualsExpression,
        ItemInListExpression,
        ItemNotInListExpression,
        ListContainsItemExpression,
        ListNotContainsItemExpression,
        KeyInDictExpression,
        KeyNotInDictExpression,
        IsDefinedExpression,
        IsNotDefinedExpression,
        LessThanExpression,
        LessThanOrEqualToExpression,
        GreaterThanExpression,
        GreaterThanOrEqualToExpression,
        NegateExpression,
        SearchMatchesExpression,
        SearchNotMatchesExpression,
        SelectExpression,
        SelectNotExpression,
        SelectAttrExpression,
        SelectAttrNotExpression,
    ]

    def trace_ast_tree(self, condition: dict, policy_name: str, depth=0, counter=None) -> tuple[RegoFunc, list]:
        funcs = []

        if counter is None:
            counter = {}
        if depth not in counter:
            counter[depth] = 0

        current_func = RegoFunc()
        counter[depth] += 1
        node_id = f"{depth}_{counter[depth]}"
        func_name = f"{policy_name}_{node_id}"
        current_func.name = func_name

        handler = self.get_handler(condition)
        if handler:
            current_func, _funcs = handler(condition, func_name, policy_name, depth, counter)
            funcs.extend(_funcs)
        return current_func, funcs

    def get_handler(self, condition):
        if self.AndAllExpression.match(condition):
            return self.handle_and_all_expression
        elif self.OrAnyExpression.match(condition):
            return self.handle_or_any_expression
        elif self.NotAllExpression.match(condition):
            return self.handle_not_all_expression
        elif self.match_operator_exp(condition):
            return self.handle_operator_expression
        else:
            return self.handle_non_operator_expression

    def match_operator_exp(self, condition):
        for exp in self.simple_expressions:
            if exp.match(condition):
                return True
        return False

    def handle_and_all_expression(self, condition, func_name, policy_name, depth, counter):
        funcs = []
        conditions = []
        if "AndExpression" in condition:
            lhs_condition = condition["AndExpression"]["lhs"]
            lhs_root_func, _funcs = self.trace_ast_tree(lhs_condition, policy_name, depth + 1, counter)
            funcs.extend(_funcs)
            conditions.append(lhs_root_func.name)

            rhs_condition = condition["AndExpression"]["rhs"]
            rhs_root_func, _funcs = self.trace_ast_tree(rhs_condition, policy_name, depth + 1, counter)
            funcs.extend(_funcs)
            conditions.append(rhs_root_func.name)

        if "AllCondition" in condition:
            for cond in condition["AllCondition"]:
                root_func, _funcs = self.trace_ast_tree(cond, policy_name, depth + 1, counter)
                funcs.extend(_funcs)
                conditions.append(root_func.name)

        and_func = self.AndAllExpression.make_rego(func_name, conditions)
        current_func = RegoFunc(name=func_name, body=and_func)
        funcs.append(current_func)

        return current_func, funcs

    def handle_or_any_expression(self, condition, func_name, policy_name, depth, counter):
        funcs = []
        conditions = []
        if "OrExpression" in condition:
            lhs_condition = condition["OrExpression"]["lhs"]
            lhs_root_func, _funcs = self.trace_ast_tree(lhs_condition, policy_name, depth, counter)
            funcs.extend(_funcs)
            conditions.append(lhs_root_func.name)

            rhs_condition = condition["OrExpression"]["rhs"]
            rhs_root_func, _funcs = self.trace_ast_tree(rhs_condition, policy_name, depth, counter)
            funcs.extend(_funcs)
            conditions.append(rhs_root_func.name)

        if "AnyCondition" in condition:
            for cond in condition["AnyCondition"]:
                root_func, _funcs = self.trace_ast_tree(cond, policy_name, depth, counter)
                funcs.extend(_funcs)
                conditions.append(root_func.name)

        or_func = self.OrAnyExpression.make_rego(func_name, conditions)
        current_func = RegoFunc(name=func_name, body=or_func)
        funcs.append(current_func)

        return current_func, funcs

    def handle_not_all_expression(self, condition, func_name, policy_name, depth, counter):
        funcs = []
        conditions = []
        for cond in condition["NotAllCondition"]:
            root_func, _funcs = self.trace_ast_tree(cond, policy_name, depth + 1, counter)
            funcs.extend(_funcs)
            conditions.append(root_func.name)

        and_func = self.NotAllExpression.make_rego(func_name, conditions)
        current_func = RegoFunc(name=func_name, body=and_func)
        funcs.append(current_func)

        return current_func, funcs

    def handle_operator_expression(self, condition, func_name, policy_name, depth, counter):
        funcs = []
        used_util_funcs = []
        func_body = ""
        for exp in self.simple_expressions:
            if exp.match(condition):
                used_util_funcs = exp.util_funcs
                func_body = exp.make_rego(func_name, condition)
        current_func = RegoFunc(name=func_name, body=func_body, util_funcs=used_util_funcs)
        funcs.append(current_func)
        return current_func, funcs

    # TODO: Change to Class
    def handle_non_operator_expression(self, condition, func_name, policy_name, depth, counter):
        funcs = []
        used_util_funcs = []
        func_body = ""
        if isinstance(condition, dict) and "String" in condition:
            func_body = f'"{condition["String"]}"'
        elif isinstance(condition, dict) and "Input" in condition:
            func_body = condition["Input"]
        elif isinstance(condition, dict) and "Variable" in condition:
            func_body = condition["Variable"]
        elif isinstance(condition, dict) and "Boolean" in condition:
            func_body = condition["Boolean"]
        elif isinstance(condition, dict) and "Integer" in condition:
            func_body = condition["Integer"]
        elif isinstance(condition, dict) and "Float" in condition:
            func_body = condition["Float"]
        elif isinstance(condition, dict) and "NullType" in condition:
            func_body = "null"
        else:
            func_body = ""
        rego_block = if_func.safe_substitute(
            {
                "func_name": func_name,
                "steps": func_body,
            }
        )
        current_func = RegoFunc(name=func_name, body=rego_block, util_funcs=used_util_funcs)
        funcs.append(current_func)
        return current_func, funcs


def join_with_separator(str_or_list: str | list, separator: str = "\n    "):
    value = ""
    if isinstance(str_or_list, str):
        value = str_or_list
    elif isinstance(str_or_list, list):
        value = separator.join(str_or_list)
    return value