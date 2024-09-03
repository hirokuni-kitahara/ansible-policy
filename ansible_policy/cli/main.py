import os
import sys
import argparse
from ansible_policy.config import Config, default_config_filename, Plugin
from ansible_policy.evaluate import PolicyEvaluator
from ansible_policy.languages.opa.policy_engine import OPAEngine
from ansible_policy.languages.opa.policy_transpiler import OPATranspiler
from ansible_policy.result_summarizer import DefaultSummarizer
from ansible_policy.result_formatter import ResultFormatter


def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('-p', '--project', type=str, help='path to a target Ansible contents (directory or file) or JSON file')
    parser.add_argument('--policy-dir', type=str, help='path to a file or directory to policies')
    parser.add_argument("-f", "--format", default="plain", help="output format (`plain` or `json`, default to `plain`)")
    parser.add_argument('-c', '--config', type=str, default='', help='path to a config file')
    
    args = parser.parse_args()

    config_path = ""
    # if a config path is specified, use it
    if args.config:
        config_path = args.config
    elif args.policy_dir:
        # if a policy dir is specified, check if "ansible-policy.cfg" exists there
        _path = os.path.join(args.policy_dir, default_config_filename)
        # use it if it exists
        if os.path.exists(_path):
            config_path = _path

    plugins = None
    # if any config file is found, load plugins based on it
    if config_path:
        config = Config.load(config_path)
        plugins = config.plugin.plugins

    evaluator = PolicyEvaluator(plugins=plugins)
    result = evaluator.run(args.policy_dir, args.project)
    if not result:
        raise ValueError('Evaluation result is empty')
    
    ResultFormatter(format_type=args.format, base_dir=os.getcwd()).print(result=result)
    violation_num = result.summary.policies.get("violation_detected", 0)
    if violation_num > 0:
        sys.exit(1)



if __name__ == "__main__":
    main()
