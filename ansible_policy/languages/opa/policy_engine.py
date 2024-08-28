import os
import subprocess
import json
import tempfile
from dataclasses import dataclass, field
from ansible_policy.models import Policy, TargetType, SingleResult, ValidationType, ActionType
from ansible_policy.interfaces.policy_input import PolicyInput
from ansible_policy.utils import init_logger, match_str_expression
from ansible_policy.interfaces.policy_engine import PolicyEngine


logger = init_logger(__name__, os.getenv("ANSIBLE_POLICY_LOG_LEVEL", "info"))


@dataclass
class OPAEngine(PolicyEngine):
    workdir: str = ""

    def __post_init__(self):
        self.validate_opa_installation()

        tmp_dir = tempfile.TemporaryDirectory()
        self.workdir = tmp_dir.name
    
    def validate_opa_installation(self, executable_name: str = "opa"):
        proc = subprocess.run(
            f"which {executable_name}",
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.stdout and proc.returncode == 0:
            return
        else:
            raise ValueError("`opa` command is required to evaluate OPA policies")

    def eval_single_policy(self, policy: Policy, input_data: PolicyInput, external_data_path: str) -> tuple[bool, dict]:
        input_data_str = input_data.dumps()
        result = eval_opa_policy(
            rego_path=policy.path,
            input_data=input_data_str,
            external_data_path=external_data_path,
        )
        return True, result

    def evaluate(self, policy: Policy, input_data: PolicyInput, external_data_path: str="") -> SingleResult:
        # if policy path is empty, it is not saved as a file yet. do it here
        if not policy.path:
            package_name = policy.metadata.attrs.get("package", "__no_package_found__")
            policy_path = os.path.join(self.workdir, f"{package_name}.rego")
            policy.save(filepath=policy_path, update_path=True)

        # obj = input_data.object
        # target_name = getattr(obj, "name", None)
        # filepath = "__no_filepath__"
        # if hasattr(obj, "filepath"):
        #     filepath = getattr(obj, "filepath")

        # lines = None
        # body = ""
        # metadata = {}
        # if policy.metadata.target == TargetType.EVENT:
        #     lines = {
        #         "begin": obj.line,
        #         "end": None,
        #     }
        #     filepath = obj.uuid
        #     metadata = obj.__dict__
        # elif policy.metadata.target == TargetType.REST:
        #     pass
        # else:
        #     with open(filepath, "r") as f:
        #         body = f.read()
        #     if input_data.type in ["task", "play"]:
        #         _identifier = LineIdentifier()
        #         block = _identifier.find_block(body=body, obj=obj)
        #         lines = block.to_dict()

        policy_name = get_rego_main_package_name(rego_path=policy.path)
        is_target_type, raw_eval_result = self.eval_single_policy(
            policy=policy,
            input_data=input_data,
            external_data_path=external_data_path,
        )
        validation = ValidationType.from_eval_result(eval_result=raw_eval_result, is_target_type=is_target_type)
        action_type = ActionType.from_eval_result(eval_result=raw_eval_result, is_target_type=is_target_type)
        single_result = SingleResult(
            target_type=input_data.type,
            target_name=input_data.name,
            filepath=input_data.filepath,
            policy_name=policy_name,
            validation=validation,
            action_type=action_type,
            target_type_matched=is_target_type,
            detail=raw_eval_result,
            lines=input_data.lines,
            metadata=input_data.metadata,
        )
        return single_result



def get_rego_main_package_name(rego_path: str):
    pkg_name = ""
    with open(rego_path, "r") as file:
        prefix = "package "
        for line in file:
            _line = line.strip()
            if _line.startswith(prefix):
                pkg_name = _line[len(prefix) :]
                break
    return pkg_name


def eval_opa_policy(rego_path: str, input_data: str, external_data_path: str, executable_name: str = "opa"):
    rego_pkg_name = get_rego_main_package_name(rego_path=rego_path)
    if not rego_pkg_name:
        raise ValueError("`package` must be defined in the rego policy file")

    external_data_option = ""
    if external_data_path:
        external_data_option = f"--data {external_data_path}"
    cmd_str = f"{executable_name} eval --data {rego_path} {external_data_option} --stdin-input 'data.{rego_pkg_name}'"
    proc = subprocess.run(
        cmd_str,
        shell=True,
        input=input_data,
        # stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    logger.debug(f"command: {cmd_str}")
    logger.debug(f"proc.input_data: {input_data}")
    logger.debug(f"proc.stdout: {proc.stdout}")
    logger.debug(f"proc.stderr: {proc.stderr}")

    if proc.returncode != 0:
        error = f"failed to run `opa eval` command; error details:\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
        raise ValueError(error)

    result = json.loads(proc.stdout)
    if "result" not in result:
        raise ValueError(f"`result` field does not exist in the output from `opa eval` command; raw output: {proc.stdout}")

    result_arr = result["result"]
    if not result_arr:
        raise ValueError(f"`result` field in the output from `opa eval` command has no contents; raw output: {proc.stdout}")

    first_result = result_arr[0]
    if not first_result and "expressions" not in first_result:
        raise ValueError(f"`expressions` field does not exist in the first result of output from `opa eval` command; first_result: {first_result}")

    expressions = first_result["expressions"]
    if not expressions:
        raise ValueError(f"`expressions` field in the output from `opa eval` command has no contents; first_result: {first_result}")

    expression = expressions[0]
    result_value = expression.get("value", {})
    eval_result = {
        "value": result_value,
        "message": proc.stderr,
    }
    return eval_result