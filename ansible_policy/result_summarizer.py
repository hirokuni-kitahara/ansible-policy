from dataclasses import dataclass, field
from typing import List
from ansible_policy.models import SingleResult, FileResult, PolicyResult, TargetResult, EvaluationResult, EvaluationSummary, ValidationType


@dataclass
class DefaultSummarizer(object):

    def run(self, results: List[SingleResult]) -> EvaluationResult:
        final_result = EvaluationResult()
        for single_result in results:
            final_result.add_single_result(single_result)
        return final_result

