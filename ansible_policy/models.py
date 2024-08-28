import os
from dataclasses import dataclass, field
from typing import List, Dict, Self


class TargetType:
    PLAY = "play" 
    TASK = "task" 
    EVENT = "event" 
    REST = "rest" 


target_types = [
    TargetType.PLAY,
    TargetType.TASK,
    TargetType.EVENT,
    TargetType.REST,
]


@dataclass
class PolicyMetadata(object):
    target: str = ""
    tags: List[str] = field(default_factory=list)
    target_module: str = ""
    dependency: List[str] = field(default_factory=list)
    attrs: Dict[str, any] = field(default_factory=dict)



@dataclass
class Policy(object):
    path: str = ""
    name: str = ""
    is_policybook: bool = False
    language: str = ""
    metadata: PolicyMetadata = field(default_factory=PolicyMetadata)
    body: str = ""
    policybook_data: any = None
    
    @classmethod
    def load(cls, filepath: str) -> Self:

        policy = cls()
        body = ""
        with open(filepath, "r") as f:
            body = f.read()
        policy.path = filepath
        policy.body = body
        return policy
    
    def save(self, filepath: str="", update_path: bool=False) -> None:
        if not filepath:
            filepath = self.path
        dir_path = os.path.dirname(filepath)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)
        with open(filepath, "w") as f:
            f.write(self.body)
        if update_path:
            self.path = filepath
        return


class ValidationType:
    SUCCESS = True
    FAILURE = False
    NONE = None

    @staticmethod
    def from_eval_result(eval_result: dict, is_target_type: bool):
        if not is_target_type:
            return ValidationType.NONE

        eval_result_value = eval_result.get("value", {})
        violation = False
        if "deny" in eval_result_value:
            if eval_result_value["deny"]:
                violation = True
        elif "allow" in eval_result_value:
            if not eval_result_value["allow"]:
                violation = True
        elif "warn" in eval_result_value:
            if eval_result_value["warn"]:
                violation = True
        elif "info" in eval_result_value:
            if eval_result_value["info"]:
                violation = True
        elif "ignore" in eval_result_value:
            if not eval_result_value["ignore"]:
                violation = True
        elif "permit" in eval_result_value:
            if not eval_result_value["permit"]:
                violation = True
        elif "forbid" in eval_result_value:
            if eval_result_value["forbid"]:
                violation = True
        if violation:
            return ValidationType.FAILURE
        else:
            return ValidationType.SUCCESS


class ActionType:
    DENY = "deny"
    ALLOW = "allow"
    INFO = "info"
    WARN = "warn"
    IGNORE = "ignore"
    NONE = None

    @staticmethod
    def from_eval_result(eval_result: dict, is_target_type: bool):
        if not is_target_type:
            return ActionType.NONE

        eval_result_value = eval_result.get("value", {})
        if "deny" in eval_result_value:
            return ActionType.DENY
        elif "allow" in eval_result_value:
            return ActionType.ALLOW
        elif "info" in eval_result_value:
            return ActionType.INFO
        elif "warn" in eval_result_value:
            return ActionType.WARN
        elif "ignore" in eval_result_value:
            return ActionType.IGNORE
        else:
            return ActionType.NONE


@dataclass
class TargetResult(object):
    name: str = None
    lines: dict = field(default_factory=dict)
    validated: bool = None
    action_type: str = ""
    message: str = None


@dataclass
class PolicyResult(object):
    policy_name: str = None
    target_type: str = None
    violation: bool = False
    targets: List[TargetResult] = field(default_factory=list)

    def add_target_result(self, target_name: str, lines: dict, validated: bool, message: str, action_type: str):
        target = TargetResult(name=target_name, lines=lines, validated=validated, message=message, action_type=action_type)
        if isinstance(validated, bool) and not validated:
            if action_type == "deny" or action_type == "allow":
                self.violation = True
        self.targets.append(target)


@dataclass
class FileResult(object):
    path: str = None
    violation: bool = False
    policies: List[PolicyResult] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def add_policy_result(
        self,
        validation: bool,
        action_type: str,
        message: str,
        is_target_type: bool,
        policy_name: str,
        target_type: str,
        target_name: str,
        lines: dict,
    ):
        policy_result = self.get_policy_result(policy_name=policy_name)
        need_append = False
        if not policy_result:
            policy_result = PolicyResult(
                policy_name=policy_name,
                target_type=target_type,
            )
            need_append = True
        if is_target_type:
            policy_result.add_target_result(target_name=target_name, lines=lines, validated=validation, message=message, action_type=action_type)
        if need_append:
            self.policies.append(policy_result)

        if any([p.violation for p in self.policies]):
            self.violation = True
        return

    def get_policy_result(self, policy_name: str):
        for p in self.policies:
            if p.policy_name == policy_name:
                return p
        return None


@dataclass
class EvaluationSummary(object):
    policies: dict = field(default_factory=dict)
    files: dict = field(default_factory=dict)

    @staticmethod
    def from_files(files: List[FileResult]):
        total_files = len(files)
        file_names = []
        violation_files = 0
        policy_names = []
        violation_policy_names = []
        for f in files:
            for p in f.policies:
                if p.policy_name not in policy_names:
                    policy_names.append(p.policy_name)
                if p.violation and p.policy_name not in violation_policy_names:
                    violation_policy_names.append(p.policy_name)
            if f.violation:
                violation_files += 1
            if f.path not in file_names:
                file_names.append(f.path)
        total_policies = len(policy_names)
        violation_policies = len(violation_policy_names)
        policies_data = {
            "total": total_policies,
            "violation_detected": violation_policies,
            "list": policy_names,
        }
        files_data = {
            "total": total_files,
            "validated": total_files - violation_files,
            "not_validated": violation_files,
            "list": file_names,
        }
        return EvaluationSummary(
            policies=policies_data,
            files=files_data,
        )


@dataclass
class SingleResult(object):
    target_type: str = None
    target_name: str = None
    filepath: str = None
    policy_name: str = None
    validation: ValidationType = None
    action_type: str = None
    target_type_matched: bool = None
    detail: dict = field(default_factory=dict)
    lines: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)


@dataclass
class EvaluationResult(object):
    summary: EvaluationSummary = None
    files: List[FileResult] = field(default_factory=list)
    
    def add_single_result(
        self,
        single_result: SingleResult,
    ):
        filepath = single_result.filepath
        policy_name = single_result.policy_name
        target_type = single_result.target_type
        target_name = single_result.target_name
        validation = single_result.validation
        action_type = single_result.action_type
        message = single_result.detail.get("message", "")
        is_target_type = single_result.target_type_matched
        lines = single_result.lines
        metadata = single_result.metadata
        file_result = self.get_file_result(filepath=filepath)
        need_append = False
        if not file_result:
            file_result = FileResult(
                path=filepath,
                metadata=metadata,
            )
            need_append = True

        file_result.add_policy_result(
            validation=validation,
            action_type=action_type,
            message=message,
            is_target_type=is_target_type,
            policy_name=policy_name,
            target_type=target_type,
            target_name=target_name,
            lines=lines,
        )
        if need_append:
            self.files.append(file_result)

        self.summary = EvaluationSummary.from_files(self.files)
        return

    def get_file_result(self, filepath: str):
        for f in self.files:
            if f.path == filepath:
                return f
        return None
