import os
import re
import base64
import json
import yaml
from rapidfuzz.distance import Levenshtein
import tarfile
import zipfile
import tempfile
import logging
import subprocess
from typing import Dict, Tuple
from importlib.util import spec_from_file_location, module_from_spec
import os
import traceback
from inspect import isclass

from ansible_policy.interfaces.policy_engine import PolicyEngine
from ansible_policy.interfaces.policy_transpiler import PolicyTranspiler
from ansible_policy.interfaces.result_summarizer import ResultSummarizer
from ansible_policy.interfaces.policy_input import PolicyInputFromJSON


default_target_type = "task"


def init_logger(name: str, level: str):
    log_level_map = {
        "error": logging.ERROR,
        "warning": logging.WARNING,
        "info": logging.INFO,
        "debug": logging.DEBUG,
    }

    level_val = log_level_map.get(level.lower(), None)
    logging.basicConfig(level=level_val)
    logger = logging.getLogger()
    return logger


logger = init_logger(__name__, os.getenv("ANSIBLE_POLICY_LOG_LEVEL", "info"))


def load_galaxy_data(fpath: str):
    data = {}
    with open(fpath, "r") as file:
        data = json.load(file)
    if not data:
        raise ValueError("loaded galaxy data is empty")

    return data.get("galaxy", {})


def get_module_name_from_task(task):
    module_name = ""
    if task.module_info and isinstance(task.module_info, dict):
        module_name = task.module_info.get("fqcn", "")
    if task.annotations:
        if not module_name:
            module_name = task.get_annotation("module.correct_fqcn", "")
        if not module_name:
            module_name = task.get_annotation("correct_fqcn", "")

    if not module_name:
        module_name = task.module

    module_short_name = module_name
    if "." in module_short_name:
        module_short_name = module_short_name.split(".")[-1]

    return module_name, module_short_name


def embed_module_info_with_galaxy(task, galaxy):
    if not task.module:
        return

    if not galaxy:
        galaxy = {}

    mappings = galaxy.get("module_name_mappings", {})

    module_fqcn = ""
    if "." in task.module:
        module_fqcn = task.module
    else:
        found = mappings.get(task.module, [])
        if found and found[0] and "." in found[0]:
            module_fqcn = found[0]
            task.module_fqcn = module_fqcn
    if not task.module_info and module_fqcn and "." in module_fqcn:
        collection_name = ".".join(module_fqcn.split(".")[:2])
        short_name = ".".join(module_fqcn.split(".")[2:])
        task.module_info = {
            "collection": collection_name,
            "fqcn": module_fqcn,
            "key": "__unknown__",
            "short_name": short_name,
        }
    return


def uncompress_file(fpath: str):
    if fpath.endswith(".tar.gz"):
        tar = tarfile.open(fpath, "r:gz")
        tar.extractall()
        tar.close()
    return


def prepare_project_dir_from_runner_jobdata(jobdata: str, workdir: str):
    if not isinstance(jobdata, str):
        return None
    lines = jobdata.splitlines()
    if not lines:
        return None
    # remove empty line
    lines = [line for line in lines if line]

    base64_zip_body = lines[-1].replace('{"eof": true}', "")
    zip_bytes = decode_base64_string(base64_zip_body)
    file = tempfile.NamedTemporaryFile(dir=workdir, delete=False, suffix=".zip")
    filepath = file.name
    with open(filepath, "wb") as file:
        file.write(zip_bytes)
    with zipfile.ZipFile(filepath) as zfile:
        zfile.extractall(path=workdir)

    return


def decode_base64_string(encoded: str) -> bytes:
    decoded_bytes = base64.b64decode(encoded.encode())
    # decoded bytes may contain some chars that cannot be converted into text string
    # so we just return the bytes data here
    return decoded_bytes


ExternalDataTypeGalaxy = "galaxy"
ExternalDataTypeAutomation = "automation"
supported_external_data_types = [ExternalDataTypeGalaxy, ExternalDataTypeAutomation]


def load_external_data(ftype: str = "", fpath: str = ""):
    if ftype not in supported_external_data_types:
        raise ValueError(f"`{ftype}` is not supported as external data")

    if fpath.endswith(".tar.gz"):
        new_fpath = fpath[:-7]
        if not os.path.exists(new_fpath):
            uncompress_file(fpath)
        fpath = new_fpath

    ext_data = None
    if ftype == ExternalDataTypeGalaxy:
        if fpath:
            ext_data = load_galaxy_data(fpath=fpath)
    else:
        raise NotImplementedError
    return ext_data


def match_str_expression(pattern: str, text: str):
    if not pattern:
        return True

    if pattern == "*":
        return True

    if "*" in pattern:
        pattern = pattern.replace("*", ".*")
        return re.match(pattern, text)

    return pattern == text


def install_galaxy_target(target, target_type, output_dir, source_repository="", target_version=""):
    server_option = ""
    if source_repository:
        server_option = "--server {}".format(source_repository)
    target_name = target
    if target_version:
        target_name = f"{target}:{target_version}"
    cmd_str = f"ansible-galaxy {target_type} install {target_name} {server_option} -p {output_dir} --force"
    logger.debug(cmd_str)
    proc = subprocess.run(
        cmd_str,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    # print("[DEBUG] stderr:", proc.stderr)
    # logger.debug("STDOUT:", proc.stdout)
    logger.debug(f"STDOUT: {proc.stdout}")
    logger.debug(f"STDERR: {proc.stderr}")
    if proc.returncode != 0:
        raise ValueError(f"failed to install a collection `{target}`; error: {proc.stderr}")
    return proc.stdout, proc.stderr


def install_galaxy_collection(name: str, target_dir: str):
    install_galaxy_target(target=name, target_type="collection", output_dir=target_dir)


def run_playbook(playbook_path: str, extra_vars: dict = None):
    extra_vars_option = ""
    if extra_vars and isinstance(extra_vars, dict):
        for key, value in extra_vars.items():
            value_str = json.dumps(value)
            extra_vars_option += f"--extra-vars='{key}={value_str}' "

    cmd_str = f"ansible-playbook {playbook_path} {extra_vars_option}"
    logger.debug(cmd_str)
    proc = subprocess.run(
        cmd_str,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    logger.debug(cmd_str)
    proc = subprocess.run(
        cmd_str,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    # print("[DEBUG] stderr:", proc.stderr)
    # logger.debug("STDOUT:", proc.stdout)
    logger.debug(f"STDOUT: {proc.stdout}")
    logger.debug(f"STDERR: {proc.stderr}")
    if proc.returncode != 0:
        raise ValueError(f"failed to run a playbook `{playbook_path}`; error: {proc.stderr}")
    return proc.stdout, proc.stderr


def transpile_yml_policy(src: str, dst: str):
    extra_vars = {
        "filepath": dst,
    }
    run_playbook(playbook_path=src, extra_vars=extra_vars)
    return


def get_tags_from_rego_policy_file(policy_path: str):
    var_name = "__tags__"
    tags = None
    with open(policy_path, "r") as file:
        for line in file:
            if var_name in line:
                parts = [p.strip() for p in line.split("=")]
                if len(parts) != 2:
                    continue
                if parts[0] == var_name:
                    tags = json.loads(parts[1])
                    break
    return tags


def find_task_line_number(
    yaml_body: str = "",
    task_name: str = "",
    module_name: str = "",
    module_options: dict = None,
    task_options: dict = None,
    previous_task_line: int = -1,
):
    if not task_name and not module_options:
        return None, None

    lines = []
    if yaml_body:
        lines = yaml_body.splitlines()

    # search candidates that match either of the following conditions
    #   - task name is included in the line
    #   - if module name is included,
    #       - if module option is string, it is included
    #       - if module option is dict, at least one key is included
    candidate_line_nums = []
    for i, line in enumerate(lines):
        # skip lines until `previous_task_line` if provided
        if previous_task_line > 0:
            if i <= previous_task_line - 1:
                continue

        if task_name:
            if task_name in line:
                candidate_line_nums.append(i)
        elif "{}:".format(module_name) in line:
            if isinstance(module_options, str):
                if module_options in line:
                    candidate_line_nums.append(i)
            elif isinstance(module_options, dict):
                option_matched = False
                for key in module_options:
                    if i + 1 < len(lines) and "{}:".format(key) in lines[i + 1]:
                        option_matched = True
                        break
                if option_matched:
                    candidate_line_nums.append(i)
    if not candidate_line_nums:
        return None, None

    # get task yaml_lines for each candidate
    candidate_blocks = []
    for candidate_line_num in candidate_line_nums:
        _yaml_lines, _line_num_in_file = _find_task_block(lines, candidate_line_num)
        if _yaml_lines and _line_num_in_file:
            candidate_blocks.append((_yaml_lines, _line_num_in_file))

    if not candidate_blocks:
        return None, None

    reconstructed_yaml = ""
    best_yaml_lines = ""
    best_line_num_in_file = []
    sorted_candidates = []
    if len(candidate_blocks) == 1:
        best_yaml_lines = candidate_blocks[0][0]
        best_line_num_in_file = candidate_blocks[0][1]
    else:
        # reconstruct yaml from the task data to calculate similarity (edit distance) later
        reconstructed_data = [{}]
        if task_name:
            reconstructed_data[0]["name"] = task_name
        reconstructed_data[0][module_name] = module_options
        if isinstance(task_options, dict):
            for key, val in task_options.items():
                if key not in reconstructed_data[0]:
                    reconstructed_data[0][key] = val

        try:
            reconstructed_yaml = yaml.safe_dump(reconstructed_data)
        except Exception:
            pass

        # find best match by edit distance
        if reconstructed_yaml:

            def remove_comment_lines(s):
                lines = s.splitlines()
                updated = []
                for line in lines:
                    if line.strip().startswith("#"):
                        continue
                    updated.append(line)
                return "\n".join(updated)

            def calc_dist(s1, s2):
                us1 = remove_comment_lines(s1)
                us2 = remove_comment_lines(s2)
                dist = Levenshtein.distance(us1, us2)
                return dist

            r = reconstructed_yaml
            sorted_candidates = sorted(candidate_blocks, key=lambda x: calc_dist(r, x[0]))
            best_yaml_lines = sorted_candidates[0][0]
            best_line_num_in_file = sorted_candidates[0][1]
        else:
            # give up here if yaml reconstruction failed
            # use the first candidate
            best_yaml_lines = candidate_blocks[0][0]
            best_line_num_in_file = candidate_blocks[0][1]

    yaml_lines = best_yaml_lines
    line_num_in_file = best_line_num_in_file
    return yaml_lines, line_num_in_file


def _find_task_block(yaml_lines: list, start_line_num: int):
    if not yaml_lines:
        return None, None

    if start_line_num < 0:
        return None, None

    lines = yaml_lines
    found_line = lines[start_line_num]
    is_top_of_block = found_line.replace(" ", "").startswith("-")
    begin_line_num = start_line_num
    indent_of_block = -1
    if is_top_of_block:
        indent_of_block = len(found_line.split("-")[0])
    else:
        found = False
        found_line = ""
        _indent_of_block = -1
        parts = found_line.split(" ")
        for i, p in enumerate(parts):
            if p != "":
                break
            _indent_of_block = i + 1
        for i in range(len(lines)):
            index = begin_line_num
            _line = lines[index]
            is_top_of_block = _line.replace(" ", "").startswith("-")
            if is_top_of_block:
                _indent = len(_line.split("-")[0])
                if _indent < _indent_of_block:
                    found = True
                    found_line = _line
                    break
            begin_line_num -= 1
            if begin_line_num < 0:
                break
        if not found:
            return None, None
        indent_of_block = len(found_line.split("-")[0])
    index = begin_line_num + 1
    end_found = False
    end_line_num = -1
    for i in range(len(lines)):
        if index >= len(lines):
            break
        _line = lines[index]
        is_top_of_block = _line.replace(" ", "").startswith("-")
        if is_top_of_block:
            _indent = len(_line.split("-")[0])
            if _indent <= indent_of_block:
                end_found = True
                end_line_num = index - 1
                break
        index += 1
        if index >= len(lines):
            end_found = True
            end_line_num = index
            break
    if not end_found:
        return None, None
    if begin_line_num < 0 or end_line_num > len(lines) or begin_line_num > end_line_num:
        return None, None

    yaml_lines = "\n".join(lines[begin_line_num : end_line_num + 1])
    line_num_in_file = [begin_line_num + 1, end_line_num + 1]
    return yaml_lines, line_num_in_file


# TODO: use task names and module names for searching
# NOTE: currently `tasks` in a Play object is composed of pre_tasks, tasks and post_tasks
def find_play_line_number(
    yaml_body: str = "",
    play_name: str = "",
    play_options: dict = None,
    task_names: list = None,
    module_names: list = None,
    previous_play_line: int = -1,
):
    if not play_name and not play_options and not task_names and not module_names:
        return None, None

    lines = []
    if yaml_body:
        lines = yaml_body.splitlines()

    # search candidates that match either of the following conditions
    #   - task name is included in the line
    #   - if module name is included,
    #       - if module option is string, it is included
    #       - if module option is dict, at least one key is included
    candidate_line_nums = []
    for i, line in enumerate(lines):
        # skip lines until `previous_task_line` if provided
        if previous_play_line > 0:
            if i <= previous_play_line - 1:
                continue

        if play_name:
            if play_name in line:
                candidate_line_nums.append(i)
        elif "hosts:":
            candidate_line_nums.append(i)
    if not candidate_line_nums:
        return None, None

    # get play yaml_lines for each candidate
    candidate_blocks = []
    for candidate_line_num in candidate_line_nums:
        _yaml_lines, _line_num_in_file = _find_play_block(lines, candidate_line_num)
        if _yaml_lines and _line_num_in_file:
            candidate_blocks.append((_yaml_lines, _line_num_in_file))

    if not candidate_blocks:
        return None, None

    reconstructed_yaml = ""
    best_yaml_lines = ""
    best_line_num_in_file = []
    sorted_candidates = []
    if len(candidate_blocks) == 1:
        best_yaml_lines = candidate_blocks[0][0]
        best_line_num_in_file = candidate_blocks[0][1]
    else:
        # reconstruct yaml from the play data to calculate similarity (edit distance) later
        reconstructed_data = [{}]
        if play_name:
            reconstructed_data[0]["name"] = play_name
        if isinstance(play_options, dict):
            for key, val in play_options.items():
                if key not in reconstructed_data[0]:
                    reconstructed_data[0][key] = val

        try:
            reconstructed_yaml = yaml.safe_dump(reconstructed_data)
        except Exception:
            pass

        # find best match by edit distance
        if reconstructed_yaml:

            def remove_comment_lines(s):
                lines = s.splitlines()
                updated = []
                for line in lines:
                    if line.strip().startswith("#"):
                        continue
                    updated.append(line)
                return "\n".join(updated)

            def calc_dist(s1, s2):
                us1 = remove_comment_lines(s1)
                us2 = remove_comment_lines(s2)
                dist = Levenshtein.distance(us1, us2)
                return dist

            r = reconstructed_yaml
            sorted_candidates = sorted(candidate_blocks, key=lambda x: calc_dist(r, x[0]))
            best_yaml_lines = sorted_candidates[0][0]
            best_line_num_in_file = sorted_candidates[0][1]
        else:
            # give up here if yaml reconstruction failed
            # use the first candidate
            best_yaml_lines = candidate_blocks[0][0]
            best_line_num_in_file = candidate_blocks[0][1]

    yaml_lines = best_yaml_lines
    line_num_in_file = best_line_num_in_file
    return yaml_lines, line_num_in_file


def _find_play_block(yaml_lines: list, start_line_num: int):
    if not yaml_lines:
        return None, None

    if start_line_num < 0:
        return None, None

    lines = yaml_lines
    found_line = lines[start_line_num]
    is_top_of_block = found_line.replace(" ", "").startswith("-")
    begin_line_num = start_line_num
    indent_of_block = -1
    if is_top_of_block:
        indent_of_block = len(found_line.split("-")[0])
    else:
        found = False
        found_line = ""
        _indent_of_block = -1
        parts = found_line.split(" ")
        for i, p in enumerate(parts):
            if p != "":
                break
            _indent_of_block = i + 1
        for i in range(len(lines)):
            index = begin_line_num
            _line = lines[index]
            is_top_of_block = _line.replace(" ", "").startswith("-")
            is_tasks_block = _line.split("#")[0].strip() in ["tasks:", "pre_tasks:", "post_tasks:"]
            if is_top_of_block and not is_tasks_block:
                _indent = len(_line.split("-")[0])
                if _indent < _indent_of_block:
                    found = True
                    found_line = _line
                    break
            begin_line_num -= 1
            if begin_line_num < 0:
                break
        if not found:
            return None, None
        indent_of_block = len(found_line.split("-")[0])
    index = begin_line_num + 1
    end_found = False
    end_line_num = -1
    for i in range(len(lines)):
        if index >= len(lines):
            break
        _line = lines[index]
        is_top_of_block = _line.replace(" ", "").startswith("-")
        if is_top_of_block:
            _indent = len(_line.split("-")[0])
            if _indent <= indent_of_block:
                end_found = True
                end_line_num = index - 1
                break
        index += 1
        if index >= len(lines):
            end_found = True
            end_line_num = index
            break
    if not end_found:
        return None, None
    if begin_line_num < 0 or end_line_num > len(lines) or begin_line_num > end_line_num:
        return None, None

    yaml_lines = "\n".join(lines[begin_line_num : end_line_num + 1])
    line_num_in_file = [begin_line_num + 1, end_line_num + 1]
    return yaml_lines, line_num_in_file


def load_classes_in_dir(dir_path: str, target_class: type, base_dir: str = "", first_one: bool = True, only_subclass: bool = True, fail_on_error: bool = False):
    search_path = dir_path
    found = False
    if os.path.exists(search_path):
        found = True
    if not found and base_dir:
        self_path = os.path.abspath(base_dir)
        search_path = os.path.join(os.path.dirname(self_path), dir_path)
        if os.path.exists(search_path):
            found = True

    if not found:
        raise ValueError(f'Path not found "{dir_path}"')

    files = os.listdir(search_path)
    scripts = [os.path.join(search_path, f) for f in files if f[-3:] == ".py"]
    classes = []
    errors = []
    for s in scripts:
        try:
            short_module_name = os.path.basename(s)[:-3]
            spec = spec_from_file_location(short_module_name, s)
            mod = module_from_spec(spec)
            spec.loader.exec_module(mod)
            for k in mod.__dict__:
                cls = getattr(mod, k)
                if not callable(cls):
                    continue
                if not isclass(cls):
                    continue
                if not issubclass(cls, target_class):
                    continue
                if only_subclass and cls == target_class:
                    continue
                classes.append(cls)
                if first_one:
                    break
        except Exception:
            exc = traceback.format_exc()
            msg = f"failed to load a rule module {s}: {exc}"
            if fail_on_error:
                raise ValueError(msg)
            else:
                errors.append(msg)
    return classes, errors


def load_plugin_set(path: str) -> Tuple[PolicyEngine, PolicyTranspiler, ResultSummarizer, Dict[str, type]]:
    engine_classes, errors = load_classes_in_dir(path, PolicyEngine, only_subclass=True, first_one=True)
    engine = None
    if engine_classes:
        engine = engine_classes[0]()

    transpiler_classes, errors = load_classes_in_dir(path, PolicyTranspiler, only_subclass=True, first_one=True)
    transpiler = None
    if transpiler_classes:
        transpiler = transpiler_classes[0]()

    summarizer_classes, errors = load_classes_in_dir(path, ResultSummarizer, only_subclass=True, first_one=True)
    summarizer = None
    if summarizer_classes:
        summarizer = summarizer_classes[0]()

    input_classes, errors = load_classes_in_dir(path, PolicyInputFromJSON, only_subclass=True, first_one=True)
    custom_types = {}
    if input_classes:
        for input_class in input_classes:
            type_name = input_class().type
            custom_types[type_name] = input_class

    return engine, transpiler, summarizer, custom_types

