import os

from dataclasses import dataclass, field
import jsonpickle
import json
from typing import List, Dict
from ansible_content_capture.scanner import AnsibleScanner
from ansible_content_capture.models import ScanResult

from ansible_policy.interfaces.policy_input import PolicyInput, PolicyInputFromJSON
from ansible_policy.policy_input import (
    PolicyInputTask,
    PolicyInputPlay,
    PolicyInputEvent,
    PolicyInputRESTData,
    load_input_from_project_dir,
    load_input_from_json_file,
    load_input_from_event,
    load_input_from_rest_data,
)


@dataclass
class TargetLoader(object):
    def run(self, target_type: str, target_path: str, raw_ansible_file: str="") -> List[PolicyInput]:
        pass


@dataclass
class TargetLoaderWrapper(TargetLoader):
    loaders: Dict[str, TargetLoader] = field(default_factory=dict)
    custom_types: Dict[str, type] = field(default_factory=dict)

    def run(self, target_type: str, target_path: str, raw_ansible_file: str="") -> List[PolicyInput]:
        loader = self.loaders.get(target_type)
        if not loader:
            loader = JSONTargetLoader(custom_types=self.custom_types)
        return loader.run(target_type, target_path, raw_ansible_file)


@dataclass
class AnsibleTargetLoader(TargetLoader):
    data_cache: dict = field(default_factory=dict)
    scanner: AnsibleScanner = None

    def __post_init__(self):
        self.scanner = AnsibleScanner(silent=True)

    def run(self, target_type: str, target_path: str, raw_ansible_file: str="") -> List[PolicyInput]:
        # if there is a cache for this target type and path, return it
        found_cache = self.data_cache.get(target_type, {}).get(target_path, None)
        if found_cache:
            return found_cache
        
        # otherwise, load ansible content and make policy input
        input_data = load_input_from_project_dir(project_dir=target_path)
        input_data_for_type = input_data.get(target_type, [])
        if target_type not in ["task", "play"]:
            raise ValueError(f"target_type for AnsibleTargetLoader must be either \"task\" or \"play\", but got {target_type}")

        input_data_class = PolicyInputTask
        if target_type == "play":
            input_data_class = PolicyInputPlay
        p_input_list = []
        for single_input_data in input_data_for_type:
            obj = getattr(single_input_data, target_type)
            p_input = input_data_class.from_obj(obj)
            p_input_list.append(p_input)

        # set cache
        if target_type not in self.data_cache:
            self.data_cache[target_type] = {}
        self.data_cache[target_type][target_path] = p_input_list

        return p_input_list


@dataclass
class EventTargetLoader(object):
    data_cache: dict = field(default_factory=dict)

    def run(self, target_type: str, target_path: str, raw_ansible_file: str="") -> List[PolicyInput]:
        # if there is a cache for this target type and path, return it
        found_cache = self.data_cache.get(target_type, {}).get(target_path, None)
        if found_cache:
            return found_cache
        
        # otherwise, load event data and make policy input
        data = None
        with open(target_path, "r") as f:
            data = json.load(f)
        input_data = load_input_from_event(event=data)
        input_data_for_type = input_data.get("event", [])
        p_input_list = []
        input_data_class = PolicyInputEvent
        for single_input_data in input_data_for_type:
            obj = getattr(single_input_data, "event")
            p_input = input_data_class.from_obj(obj)
            setattr(p_input, "filepath", target_path)
            p_input_list.append(p_input)
        return p_input_list



@dataclass
class RESTTargetLoader(object):
    data_cache: dict = field(default_factory=dict)

    def run(self, target_type: str, target_path: str, raw_ansible_file: str="") -> List[PolicyInput]:
        # if there is a cache for this target type and path, return it
        found_cache = self.data_cache.get(target_type, {}).get(target_path, None)
        if found_cache:
            return found_cache
        
        # otherwise, load REST data and make policy input
        data = None
        with open(target_path, "r") as f:
            data = json.load(f)
        input_data = load_input_from_rest_data(rest_data=data)
        input_data_for_type = input_data.get("rest", [])
        p_input_list = []
        input_data_class = PolicyInputRESTData
        for single_input_data in input_data_for_type:
            obj = getattr(single_input_data, "rest")
            p_input = input_data_class.from_obj(obj)
            setattr(p_input, "filepath", target_path)
            p_input_list.append(p_input)
        return p_input_list


@dataclass
class JSONTargetLoader(TargetLoader):
    custom_types: Dict[str, type] = field(default_factory=dict)

    def run(self, target_type: str, target_path: str, raw_ansible_file: str="") -> List[PolicyInput]:
        input_data = load_input_from_json_file(filepath=target_path)
        input_data_for_type = input_data.get("json", [])
        p_input_list = []
        input_data_class = self.custom_types.get(target_type, PolicyInputFromJSON)
        for single_input_data in input_data_for_type:
            obj = getattr(single_input_data, "json")
            p_input = input_data_class.from_json(obj)
            setattr(p_input, "filepath", target_path)
            p_input_list.append(p_input)
        return p_input_list