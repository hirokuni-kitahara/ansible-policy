import os
from dataclasses import dataclass, field
from typing import List, Dict

from ansible_policy.config import Plugin
from ansible_policy.models import EvaluationResult, Policy, TargetType, target_types
from ansible_policy.policy_loader import PolicyLoader
from ansible_policy.target_loader import TargetLoader, TargetLoaderWrapper, AnsibleTargetLoader, EventTargetLoader, RESTTargetLoader
from ansible_policy.result_summarizer import DefaultSummarizer
from ansible_policy.utils import (
    init_logger,
)


logger = init_logger(__name__, os.getenv("ANSIBLE_POLICY_LOG_LEVEL", "info"))


@dataclass
class PolicyEvaluator(object):
    # required
    plugins: List[Plugin] = field(default_factory=list)

    # automatically set
    policy_loader: PolicyLoader = None
    target_loader: TargetLoader = None

    _custom_types: Dict[str, type] = field(default_factory=dict)
    _default_plugin: Plugin = None

    def __post_init__(self):
        if not self.plugins:
            raise ValueError("at least one plugin is required")
        
        default_plugin = None
        custom_types = {}
        for p in self.plugins:
            if p.name == "default":
                default_plugin = p
            if p.custom_types:
                custom_types.update(p.custom_types)
        if not default_plugin:
            raise ValueError("A plugin named `default` must be provided for evaluator")
        
        if not default_plugin.summarizer:
            default_plugin.summarizer = DefaultSummarizer()

        self._default_plugin = default_plugin
        self._custom_types = custom_types

        self.policy_loader = PolicyLoader(
            transpiler=default_plugin.transpiler,
        )
        _ansible_target_loader = AnsibleTargetLoader()
        self.target_loader = TargetLoaderWrapper(
            loaders={
                TargetType.PLAY: _ansible_target_loader,
                TargetType.TASK: _ansible_target_loader,
                TargetType.EVENT: EventTargetLoader(),
                TargetType.REST: RESTTargetLoader(),
            },
            custom_types=custom_types,
        )

    def get_plugin(self, name: str) -> Plugin:
        for p in self.plugins:
            if p.name == name:
                return p
        return self._default_plugin

    def run(self, policy_path: str, target_path: str) -> EvaluationResult:
        policies = self.policy_loader.run(policy_path=policy_path)
        logger.debug(f"policies: {policies}")

        single_results = []
        for policy in policies:
            if not isinstance(policy, Policy):
                msg = f"every policy must be an instance of Policy class, but found {type(policy)} instance"
                raise TypeError(msg)

            target_type = policy.metadata.target
            input_data_list = self.target_loader.run(target_type, target_path)
            if not input_data_list:
                raise ValueError(f"No input data found for \"{target_type}\"")
            
            plugin = self.get_plugin(name=target_type)
            for input_data in input_data_list:
                single_result = plugin.engine.evaluate(policy, input_data)
                single_results.append(single_result)
                
        overall_result = self._default_plugin.summarizer.run(single_results)
        return overall_result


def main():
    pass


if __name__ == "__main__":
    main()
