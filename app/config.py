import os
import uuid
import yaml

CONFIG_PATH = os.environ.get("XMONITOR_CONFIG", "config.yaml")

_config = None


def load_config() -> dict:
    global _config
    with open(CONFIG_PATH, "r") as f:
        _config = yaml.safe_load(f)

    # Auto-generate server_id if missing
    ms = _config.get("master_server", {})
    if not ms.get("server_id"):
        ms["server_id"] = str(uuid.uuid4())
        _config["master_server"] = ms
        with open(CONFIG_PATH, "w") as f:
            yaml.safe_dump(_config, f, default_flow_style=False)

    return _config


def get_config() -> dict:
    if _config is None:
        return load_config()
    return _config
