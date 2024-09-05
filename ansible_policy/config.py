import os
import re
import glob
import tempfile
from dataclasses import dataclass, field
from typing import List, Dict, Self

from ansible_policy.policybook.utils import load_policybook_dir, load_policybook_file
from ansible_policy.interfaces.policy_engine import PolicyEngine
from ansible_policy.interfaces.policy_transpiler import PolicyTranspiler
from ansible_policy.interfaces.result_summarizer import ResultSummarizer
from ansible_policy.interfaces.policy_input import PolicyInputFromJSON
from ansible_policy.models import Policy
from ansible_policy.utils import (
    init_logger,
    match_str_expression,
    get_tags_from_rego_policy_file,
    load_plugin_set,
)


logger = init_logger(__name__, os.getenv("ANSIBLE_POLICY_LOG_LEVEL", "info"))

default_config_filename = "ansible-policy.cfg"


field_re = r"\[([a-zA-Z0-9._\-]+)\]"
policy_pattern_re = r"[ ]*([^ #]*)[ ]+(tag[ ]?=[ ]?[^ ]+)?.*(enabled|disabled).*"
source_pattern_re = r"[ ]*([^ #]*)[ ]*=[ ]*([^ ]+)([ ]+type[ ]?=[ ]?[^ ]+)?.*"
plugin_pattern_re = r"[ ]*([^ #]*)[ ]*=[ ]*(.*)[ ]*"

default_policy_install_dir = "/tmp/ansible-policy/installed_policies"

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
class PolicyPattern(object):
    name: str = ""
    tags: str | list = None
    enabled: bool = None

    @staticmethod
    def load(line: str):
        matched = re.match(policy_pattern_re, line)
        if not matched:
            return None
        pp = PolicyPattern()
        name = matched.group(1)
        tags_raw = matched.group(2)
        enabled_raw = matched.group(3)
        tags = None
        if tags_raw:
            tags = tags_raw.replace(" ", "").split("=")[-1].split(",")
        enabled = True if enabled_raw == "enabled" else False if enabled_raw == "disabled" else None
        # special name
        if name == "default":
            name = "*"
        pp.name = name
        pp.tags = tags
        pp.enabled = enabled
        return pp

    def check_enabled(self, filepath: str, policy_root_dir: str):
        relative = os.path.relpath(filepath, policy_root_dir)
        parts = relative.split("/")
        policy_source_name = parts[0]
        # if name pattern does not match, just ignore this pattern by returning None
        if not match_str_expression(self.name, policy_source_name):
            return None
        # otherwise, this pattern matches the policy filepath at least in terms of its source name
        # then checks matching in detail
        if self.tags:
            pattern_tags = set()
            if isinstance(self.tags, str):
                pattern_tags.add(self.tags)
            elif isinstance(self.tags, list):
                pattern_tags = set(self.tags)

            tags = get_tags_from_rego_policy_file(policy_path=filepath)
            # it tag is specified for this pattern but the policy file does not have any tag,
            # this pattern is not related to the policy
            if not tags:
                return None
            # otherwise, checks if any tags are matched with this pattern or not

            matched_tags = pattern_tags.intersection(set(tags))
            if not matched_tags:
                return None

        return self.enabled


@dataclass
class Source(object):
    name: str = ""
    source: str = ""
    type: str = ""

    @staticmethod
    def load(line: str):
        matched = re.match(source_pattern_re, line)
        if not matched:
            return None
        name = matched.group(1)
        _source = matched.group(2)
        _type_raw = matched.group(3)
        _type = ""
        if _type_raw:
            _type = _type_raw.replace(" ", "").split("=")[-1]
        else:
            if "/" in _source and not _source.endswith(".tar.gz"):
                _type = "path"
            else:
                _type = "galaxy"
        source = Source()
        source.name = name
        source.source = _source
        source.type = _type
        return source

    def install(self, install_root_dir: str = "", force: bool = False):
        target_dir = os.path.join(install_root_dir, self.name)
        exists = False
        if os.path.exists(target_dir) and len(os.listdir(target_dir)) > 0:
            exists = True
        if exists and not force:
            return None

        logger.debug(f"Installing policies `{self.name}` to `{target_dir}`")

        policybook_dir = None
        if self.type == "path":
            policybook_dir = self.source
        elif self.type == "galaxy":
            # Do not install policies from Galaxy
            pass
        else:
            raise ValueError(f"`{self.type}` is not a supported policy type")

        policies = []
        if policybook_dir:
            if os.path.isfile(policybook_dir):
                policybook = load_policybook_file(filepath=policybook_dir)
                policy = Policy(is_policybook=True, policybook_data=policybook)
                policies.append(policy)
            else:
                policybooks = load_policybook_dir(root_dir=policybook_dir)
                for policybook in policybooks:
                    policy = Policy(is_policybook=True, policybook_data=policybook)
                    policies.append(policy)
        else:
            # TODO: policy file discovery for non-policybook policies
            pass

        return policies
    

@dataclass
class Plugin(object):
    name: str = ""
    engine: PolicyEngine = None
    transpiler: PolicyTranspiler = None
    summarizer: ResultSummarizer = None
    custom_types: Dict[str, PolicyInputFromJSON] = field(default_factory=dict)

    @classmethod
    def load(cls, name: str="", dir_path: str="", line: str=""):
        if not name and not dir_path and not line:
            raise ValueError("`name` or `line` are required to load plugin")
        if line:
            matched = re.match(plugin_pattern_re, line)
            if not matched:
                return None
            name = matched.group(1)
            dir_path = matched.group(2)
        
        engine, transpiler, summarizer, custom_types = load_plugin_set(path=dir_path)
        plugin = cls()
        plugin.name = name
        plugin.engine = engine
        plugin.transpiler = transpiler
        plugin.summarizer = summarizer
        plugin.custom_types = custom_types
        return plugin


@dataclass
class PolicyConfig(object):
    patterns: List[PolicyPattern] = field(default_factory=list)

    @staticmethod
    def from_lines(lines: list):
        config = PolicyConfig()
        for line in lines:
            # skip a line which is not setting `enabled`/`disabled`
            if "enabled" not in line and "disabled" not in line:
                continue
            pattern = PolicyPattern.load(line)
            if not pattern:
                continue
            config.patterns.append(pattern)
        return config


@dataclass
class SourceConfig(object):
    sources: list = field(default_factory=list)

    @staticmethod
    def from_lines(lines: list):
        config = SourceConfig()
        for line in lines:
            source = Source.load(line)
            if not source:
                continue
            config.sources.append(source)
        return config


@dataclass
class PluginConfig(object):
    plugins: list = field(default_factory=list)

    @staticmethod
    def from_lines(lines: list):
        config = PluginConfig()
        for line in lines:
            plugin = Plugin.load(line=line)
            if not plugin:
                continue
            config.plugins.append(plugin)
        return config


_mapping = {
    "policy": PolicyConfig,
    "source": SourceConfig,
    "plugin": PluginConfig,
}


@dataclass
class Config(object):
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    source: SourceConfig = field(default_factory=SourceConfig)
    plugin: PluginConfig = field(default_factory=PluginConfig)

    def __post_init__(self):
        pass

    @classmethod
    def load(cls, filepath: str) -> Self:
        config = cls()
        config_lines = {}
        current_field = ""
        with open(filepath, "r") as file:
            for line in file:
                _line = line.strip()
                if not _line:
                    continue

                matched = re.match(field_re, _line)
                if matched:
                    current_field = matched.group(1)
                    config_lines[current_field] = []
                else:
                    config_lines[current_field].append(_line)
        for _field, lines in config_lines.items():
            if _field not in _mapping:
                raise ValueError(f"`{_field}` is an unknown field name in a config file")
            _cls = _mapping[_field]
            single_config = _cls.from_lines(lines=lines)
            setattr(config, _field, single_config)
        return config

