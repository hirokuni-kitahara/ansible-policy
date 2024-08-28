from typing import Dict, List, NamedTuple, Union, Self
import yaml
import glob
from ansible_policy.policybook.policybook_models import Policybook
from ansible_policy.policybook.json_generator import generate_dict_policysets
from ansible_policy.policybook.policy_parser import parse_policy_sets


def load_policybook_file(filepath: str) -> Policybook:
    # policybook = Policybook()
    # policybook.filepath = filepath
    policyset = None
    with open(filepath, "r") as f:
        data = yaml.safe_load(f.read())
        policyset = generate_dict_policysets(parse_policy_sets(data))
    policybook = Policybook(
        filepath=filepath,
        policy=policyset[0],
    )
    return policybook


def load_policybook_dir(root_dir: str) -> List[Policybook]:
    pattern1 = f"{root_dir}/**/policies/**/*.yml"
    pattern2 = f"{root_dir}/**/extensions/policy/**/*.yml"
    policy_path_list = []
    _found = glob.glob(pattern1, recursive=True)
    if _found:
        policy_path_list.extend(_found)
    _found = glob.glob(pattern2, recursive=True)
    if _found:
        policy_path_list.extend(_found)
    if not policy_path_list:
        input_parts = root_dir.split("/")
        if "policies" in input_parts or "policy" in input_parts:
            pattern3 = f"{root_dir}/**/*.yml"
            _found = glob.glob(pattern3, recursive=True)
            if _found:
                policy_path_list.extend(_found)
    policy_path_list = sorted(policy_path_list)
    policybooks = []
    for p_path in policy_path_list:
        policybook = load_policybook_file(p_path)
        if policybook:
            policybooks.append(policybook)
    return policybooks
    

if __name__ == "__main__":
    policybooks = load_policybook_dir(root_dir="examples/check_project")
    for policybook in policybooks:
        print(policybook)
