import yaml

from .models import Policy


def load_policies(path: str) -> list[Policy]:
    with open(path) as f:
        data = yaml.safe_load(f)
    return [Policy(**p) for p in data["policies"]]
