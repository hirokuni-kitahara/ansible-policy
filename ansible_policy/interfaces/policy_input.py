from dataclasses import dataclass, field
from typing import Self
import json
import jsonpickle
import yaml
from dataclasses_jsonschema import JsonSchemaMixin


# Inherit this class to create a custom target type
# The custom type can be specified in a Policybook like `target: <custom_type_name>`
@dataclass
class PolicyInput(JsonSchemaMixin):
    type: str = ""
    name: str = ""
    filepath: str = ""
    lines: dict = field(default_factory=dict)

    metadata: dict = field(default_factory=dict)

    # other attrs should be implemented in each child class

    def __post_init__(self):
        if not self.type:
            raise ValueError("`type` must be a non-empty value to init PolicyInput")

    @classmethod
    def load(cls, filepath: str) -> Self:
        body = ""
        with open(filepath, "r") as f:
            body = f.read()
        return cls.loads(body)
    
    @classmethod
    def loads(cls, body: str) -> Self:
        data = {}
        err_json = None
        err_yaml = None
        try:
            data = json.loads(body)
        except Exception as ej:
            err_json = ej
            try:
                data = yaml.safe_load(body)
            except Exception as ey:
                err_yaml = ey
        if err_json and err_yaml:
            raise ValueError(f"failed to load PolicyInput; json error: {err_json}, yaml error: {err_yaml}")
        
        if not isinstance(data, dict):
            raise TypeError(f"loaded PolicyInput must be dict type, but {type(data)}")
        
        instance = cls()
        for k, v in data.items():
            if hasattr(instance, k):
                setattr(instance, k, v)
        return instance
    
    # implement this if the child class needs custom JSON serialization for dump()
    def to_dict(self) -> dict:
        raise NotImplementedError()
    
    def dumps(self, format: str="json") -> str:
        data = self
        try:
            # if `to_dict()` is implemented in a child class, use the dict data instead of instance
            data = self.to_dict()
        except Exception:
            pass

        if format == "json":
            return jsonpickle.encode(
                data,
                unpicklable=False,
                make_refs=False,
                separators=(",", ":"),
            )
        # TODO: support other format if needed?

    def dump(self, filepath: str) -> None:
        body = self.dumps()
        with open(filepath, "w") as f:
            f.write(body)


@dataclass
class PolicyInputFromJSON(PolicyInput):
    type: str = "json"

    @classmethod
    def from_json_str(cls, json_str: str) -> Self:
        data = json.loads(json_str)
        if not isinstance(data, dict):
            raise ValueError(f"loaded JSON is not a dict but {type(data)}")
        return cls.from_json(data)

    @classmethod
    def from_json(cls, data: dict) -> Self:
        input_data = cls()
        for k, v in data.items():
            setattr(input_data, k, v)
        return input_data