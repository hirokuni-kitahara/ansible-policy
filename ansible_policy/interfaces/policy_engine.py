from dataclasses import dataclass, field
from ansible_policy.models import Policy, SingleResult
from ansible_policy.interfaces.policy_input import PolicyInput

@dataclass
class PolicyEngine(object):

    def evaluate(self, policy: Policy, input_data: PolicyInput) -> SingleResult:
        raise NotImplementedError("PolicyEngine is an abstract class; Do not call evaluate() directly.")

