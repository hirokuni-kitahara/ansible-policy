from typing import Dict, List, NamedTuple, Union, Self
import yaml
import glob
import ansible_rulebook.condition_types as ct


class Action(NamedTuple):
    action: str
    action_args: dict


class Condition(NamedTuple):
    when: str
    value: List[ct.Condition]


class Policy(NamedTuple):
    name: str
    condition: Condition
    actions: List[Action]
    enabled: bool
    tags: List[str]
    target: str


class PolicySet(NamedTuple):
    name: str
    hosts: Union[str, List[str]]
    vars: Dict
    policies: List[Policy]
    match_multiple_policies: bool = False


class Policybook(NamedTuple):
    filepath: str
    policy: PolicySet
