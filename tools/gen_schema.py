import os
import sys
import json


from ansible_policy.policy_input import PolicyInputTask, PolicyInputPlay


def main():
    print(PolicyInputTask.json_schema())
    # output_dir = sys.argv[1]
    
    # with open(os.path.join(output_dir, "task_schema.json"), "w") as f:
    #     json.dump(get_schema(PolicyInputTask), f, indent=2)

    # with open(os.path.join(output_dir, "play_schema.json"), "w") as f:
    #     json.dump(get_schema(PolicyInputPlay), f, indent=2)


if __name__ == "__main__":
    main()