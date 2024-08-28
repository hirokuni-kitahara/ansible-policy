import sys
import shutil
import jsonpickle
from dataclasses import dataclass
from ansible_policy.models import EvaluationResult
from ansible_policy.policy_input import CodeBlock


EvalTypeJobdata = "jobdata"
EvalTypeProject = "project"
EvalTypeTaskResult = "task_result"
EvalTypeRest = "rest"
EvalTypeEvent = "event"

FORMAT_PLAIN = "plain"
FORMAT_EVENT_STREAM = "event_stream"
FORMAT_REST = "rest"
FORMAT_JSON = "json"
supported_formats = [FORMAT_PLAIN, FORMAT_EVENT_STREAM, FORMAT_REST, FORMAT_JSON]


@dataclass
class ResultFormatter(object):
    format_type: str = None
    isatty: bool = None
    term_width: int = None
    base_dir: str = ""

    def __post_init__(self):
        if self.format_type is None or self.format_type not in supported_formats:
            raise ValueError(f"`format_type` must be one of {supported_formats}, " "but received {self.format_type}")
        if self.isatty is None:
            self.isatty = sys.stdout.isatty()
        if self.term_width is None:
            self.term_width = shutil.get_terminal_size().columns
        return

    def print(self, result: EvaluationResult):
        if self.format_type == FORMAT_EVENT_STREAM:
            self.print_event_stream(result)
        elif self.format_type == FORMAT_JSON:
            self.print_json(result)
        elif self.format_type == FORMAT_REST:
            self.print_rest(result)
        elif self.format_type == FORMAT_PLAIN:
            self.print_plain(result)

    def print_event_stream(self, result: EvaluationResult):
        if not result.files:
            return
        file_result = result.files[0]
        if not file_result.policies:
            return

        policy_result = file_result.policies[0]
        if not policy_result.targets:
            return
        target_result = policy_result.targets[0]

        task_path = file_result.metadata.get("task_path", "")

        event_type = target_result.name
        _uuid = file_result.path
        short_uuid = _uuid[:4] + "..." + _uuid[-4:]
        file_info = task_path
        # if base_dir is provided, shorten the filepath to be shown when possible
        if self.base_dir:
            file_info = self.shorten_filepath(file_info)
        file_info = f"\033[93m{file_info}\033[00m"
        event_name = f"{event_type} {short_uuid}"
        _violated = "\033[91mViolation\033[00m" if file_result.violation else "\033[96mPass\033[00m"
        _msg = ""
        if policy_result.violation:
            _msg += target_result.message.strip()
        max_message_length = 120
        if len(_msg) > max_message_length:
            _msg = _msg[:max_message_length] + "..."
        if _msg:
            _msg = f"\n    \033[90m{_msg}\033[00m"
        _line = f"Event [{event_name}] {file_info} {_violated} {_msg}"
        print(_line)

    def print_rest(self, result: EvaluationResult):
        if not result.files:
            return
        file_result = result.files[0]
        if not file_result.policies:
            return

        policy_result = None
        target_result = None
        for p_res in file_result.policies:
            if p_res.targets:
                policy_result = p_res
                target_result = p_res.targets[0]
        if not policy_result or not target_result:
            return

        policy_name = policy_result.policy_name

        _violated = "\033[91mViolation\033[00m" if file_result.violation else "\033[96mPass\033[00m"
        _msg = ""
        if policy_result.violation:
            _msg += target_result.message.strip()
        max_message_length = 120
        if len(_msg) > max_message_length:
            _msg = _msg[:max_message_length] + "..."
        if _msg:
            _msg = f"\033[90m{_msg}\033[00m"
        _line = f"REST [{policy_name}] {_violated} {_msg}"
        print(_line)

    def print_json(self, result: EvaluationResult):
        json_str = jsonpickle.encode(
            result,
            unpicklable=False,
            make_refs=False,
            separators=(",", ":"),
        )
        print(json_str)

    def print_plain(self, result: EvaluationResult):
        not_validated_targets = []
        for f in result.files:
            filepath = f.path
            for p in f.policies:
                for t in p.targets:
                    if isinstance(t.validated, bool) and not t.validated:
                        lines = None
                        if t.lines:
                            lines = CodeBlock.dict2str(t.lines)
                        detail = {
                            "type": p.target_type,
                            "name": t.name,
                            "policy_name": p.policy_name,
                            "filepath": filepath,
                            "lines": lines,
                            "message": t.message,
                            "action_type": t.action_type,
                        }
                        not_validated_targets.append(detail)
        headers = []
        violation_per_type = {}
        warning_per_type = {}
        info_per_type = {}
        for d in not_validated_targets:
            _type = d.get("type", "")
            _type_up = _type.upper()
            name = d.get("name", "")
            policy_name = d.get("policy_name", "")
            filepath = d.get("filepath", "")
            if self.base_dir:
                filepath = self.shorten_filepath(filepath)
            lines = d.get("lines", "")
            if not lines:
                lines = ""
            message = d.get("message", "").strip()
            pattern = f"{_type} {name} {filepath} {lines}"
            if d["action_type"] == "deny" or d["action_type"] == "allow":
                _list = violation_per_type.get(_type, [])
                if pattern not in _list:
                    violation_per_type[_type] = _list + [pattern]
            if d["action_type"] == "warn":
                _list = warning_per_type.get(_type, [])
                if pattern not in _list:
                    warning_per_type[_type] = _list + [pattern]
            if d["action_type"] == "info":
                _list = info_per_type.get(_type, [])
                if pattern not in _list:
                    info_per_type[_type] = _list + [pattern]

            file_info = f"{filepath} {lines}"
            if self.isatty:
                file_info = f"\033[93m{file_info}\033[00m"
            header = f"{_type_up} [{name}] {file_info} ".ljust(self.term_width, "*")
            if header not in headers:
                print(header)
                headers.append(header)

            if d["action_type"] == "deny" or d["action_type"] == "allow":
                flag = "Not Validated"
                if self.isatty:
                    flag = f"\033[91m{flag}\033[00m"
                    message = f"\033[90m{message}\033[00m"
            elif d["action_type"] == "warn":
                flag = "Warning"
                if self.isatty:
                    flag = f"\033[33m{flag}\033[00m"
                    message = f"\033[90m{message}\033[00m"
            elif d["action_type"] == "info":
                flag = "Info"
                if self.isatty:
                    flag = f"\033[32m{flag}\033[00m"
                    message = f"\033[90m{message}\033[00m"
            print(f"... {policy_name} {flag}")
            print(f"    {message}")
            print("")
        print("-" * self.term_width)
        print("SUMMARY")
        total_files = result.summary.files.get("total", 0)
        valid_files = result.summary.files.get("validated", 0)
        not_valid_files = result.summary.files.get("not_validated", 0)
        total_label = "Total files"
        valid_label = "Validated"
        not_valid_label = "Not Validated"
        if self.isatty:
            total_label = f"\033[92m{total_label}\033[00m"
            valid_label = f"\033[96m{valid_label}\033[00m"
            not_valid_label = f"\033[91m{not_valid_label}\033[00m"
        print(f"... {total_label}: {total_files}, {valid_label}: {valid_files}, {not_valid_label}: {not_valid_files}")
        print("")
        violation_count_str = ""
        warn_count_str = ""
        info_count_str = ""
        for _type, _list in violation_per_type.items():
            count = len(_list)
            plural = ""
            if count > 1:
                plural = "s"
            violation_count_str = f"{violation_count_str}, {count} {_type}{plural}"
        for _type, _list in warning_per_type.items():
            count = len(_list)
            plural = ""
            if count > 1:
                plural = "s"
            warn_count_str = f"{warn_count_str}, {count} {_type}{plural}"
        for _type, _list in info_per_type.items():
            count = len(_list)
            plural = ""
            if count > 1:
                plural = "s"
            info_count_str = f"{info_count_str}, {count} {_type}{plural}"
        if violation_count_str:
            violation_count_str = violation_count_str[2:]
            violation_str = f"Violations are detected! in {violation_count_str}"
            if self.isatty:
                violation_str = f"\033[91m{violation_str}\033[00m"
            print(violation_str)
        if warn_count_str:
            warn_count_str = warn_count_str[2:]
            warn_str = f"Warning messages present in {warn_count_str}"
            if self.isatty:
                warn_str = f"\033[33m{warn_str}\033[00m"
            print(warn_str)
        if info_count_str:
            info_count_str = info_count_str[2:]
            info_str = f"Info messages present in {info_count_str}"
            if self.isatty:
                info_str = f"\033[32m{info_str}\033[00m"
            print(info_str)
        if not violation_count_str and not warn_count_str and not info_count_str:
            violation_str = "No violations are detected"
            if self.isatty:
                violation_str = f"\033[96m{violation_str}\033[00m"
            print(violation_str)
        print("")

    def shorten_filepath(self, filepath: str):
        _base_dir_prefix = self.base_dir
        if _base_dir_prefix[-1] != "/":
            _base_dir_prefix += "/"
        if filepath.startswith(_base_dir_prefix):
            filepath = filepath[len(_base_dir_prefix) :]
        return filepath