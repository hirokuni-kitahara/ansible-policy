from dataclasses import dataclass, field
from typing import List
from ansible_policy.models import SingleResult, EvaluationResult


@dataclass
class ResultSummarizer(object):

    def run(self, results: List[SingleResult]) -> EvaluationResult:
        raise NotImplementedError("ResultSummarizer is an abstract class; Do not call run() directly.")