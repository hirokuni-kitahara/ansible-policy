from dataclasses import dataclass, field
from typing import List, Union

from ansible_policy.models import Policy
from ansible_policy.policybook.policybook_models import Policybook


@dataclass
class PolicyTranspiler(object):
    tmp_dir: str = ""

    def run(self, policybook: Policybook) -> List[Policy]:
        raise NotImplementedError("PolicyTranspiler is an abstract class; Do not call run() directly.")
