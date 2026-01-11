import tomllib
from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple

@dataclass
class Config:
    arp_poison_warm_up: int
    arp_poison_delay: int
    arp_poison_icmp: bool
    arp_poison_reply: bool
    arp_poison_request: bool
    arp_poison_oneway: bool
    arp_skip_discovery: bool
    arp_hardcoded_group1: List[Tuple[str]]
    arp_hardcoded_group2: List[Tuple[str]]
    arp_hardcoded_interface: str

def _load() -> Config:
    path = Path(__file__).parent / "config.toml"
    with path.open("rb") as f:
        data = tomllib.load(f)
    return Config(**data["arp"])

config = _load()