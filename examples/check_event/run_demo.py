import os
from ansible_policy.evaluate import PolicyEvaluator
from ansible_policy.result_formatter import ResultFormatter, FORMAT_EVENT_STREAM


events_dir = os.path.join(os.path.dirname(__file__), "job_events")
policy_dir = os.path.join(os.path.dirname(__file__), "policies")

def get_event_filepath():
    files = os.listdir(events_dir)
    event_path_list = [os.path.join(events_dir, fname) for fname in files]
    event_path_list = sorted(event_path_list, key=lambda x: int(x.split("/")[-1].split("-")[0]))
    for event_path in event_path_list:
        yield event_path


def main():
    evaluator = PolicyEvaluator()
    formatter = ResultFormatter(format_type=FORMAT_EVENT_STREAM)
    for event_filepath in get_event_filepath():
        result = evaluator.run(
            policy_path=policy_dir,
            target_path=event_filepath,
        )
        formatter.print(result)


if __name__ == "__main__":
    main()
