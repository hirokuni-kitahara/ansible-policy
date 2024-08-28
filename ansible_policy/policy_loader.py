import os
import re
import glob
import tempfile
from dataclasses import dataclass, field
from typing import List

from ansible_policy.models import Policy
from ansible_policy.config import PolicyPattern, Source, Config
from ansible_policy.interfaces.policy_transpiler import PolicyTranspiler


@dataclass
class PolicyLoader(object):
    config_path: str = ""
    need_cleanup: bool = False
    workdir: str = ""

    patterns: List[PolicyPattern] = field(default_factory=list)
    sources: List[Source] = field(default_factory=list)

    transpiler: PolicyTranspiler = None

    def __post_init__(self):
        if not self.workdir:
            tmp_dir = tempfile.TemporaryDirectory()
            self.workdir = tmp_dir.name
            self.need_cleanup = True
        
        self.setup_and_install(config_path=self.config_path)

    def setup_and_install(self, policy_path: str="", config_path: str="") -> List[Policy]:
        if config_path:
            cfg = Config.load(filepath=config_path)
            self.patterns = cfg.policy.patterns
            self.sources = cfg.source.sources
        elif policy_path:
            policy_name = "policy"
            pattern = PolicyPattern(name=policy_name, enabled=True)
            self.patterns.append(pattern)
            source = Source(name=policy_name, source=policy_path, type="path")
            self.sources.append(source)
        return self.install()

    def install(self) -> List[Policy]:
        policies = []
        if self.sources:
            for source in self.sources:
                _policies = source.install(
                    install_root_dir=self.workdir,
                    force=False,
                )
                if _policies:
                    policies.extend(_policies)
        return policies

    def run(self, policy_path: str) -> List[Policy]:
        if not os.path.exists(policy_path):
            raise OSError(f"file not found: {policy_path}")
        
        loaded_policies = []
        if policy_path:
            loaded_policies = self.setup_and_install(policy_path=policy_path)
        policies = []
        for p in loaded_policies:
            _policies = [p]
            if p.is_policybook:
                _policies = self.transpiler.run(policybook=p.policybook_data)
            policies.extend(_policies) 
        return policies

    def list_enabled_policies(self, policy_dir):
        rego_policy_pattern_1 = os.path.join(policy_dir, "**", "policies/*.rego")
        found_files_1 = glob.glob(pathname=rego_policy_pattern_1, recursive=True)
        rego_policy_pattern_2 = os.path.join(policy_dir, "**", "extensions/policy/*/*.rego")
        found_files_2 = glob.glob(pathname=rego_policy_pattern_2, recursive=True)
        found_files = []
        if found_files_1:
            found_files.extend(found_files_1)
        if found_files_2:
            found_files.extend(found_files_2)
        # sort patterns by their name because a longer pattern is prioritized than a shorter one
        patterns = sorted(self.patterns, key=lambda x: len(x.name))

        policies_and_enabled = {}
        for policy_filepath in found_files:
            for pattern in patterns:
                enabled = pattern.check_enabled(filepath=policy_filepath, policy_root_dir=policy_dir)
                # if enabled is None, it means this pattern is not related to the policy
                if enabled is None:
                    continue
                policies_and_enabled[policy_filepath] = enabled
        enabled_policies = []
        for path, enabled in policies_and_enabled.items():
            if enabled:
                enabled_policies.append(path)
        return enabled_policies