import tomllib
from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple

@dataclass
class ArpConfig:
    poison_warm_up: int
    poison_delay: int
    poison_icmp: bool
    poison_reply: bool
    poison_request: bool
    poison_oneway: bool
    automatic_discovery: bool
    skip_discovery: bool
    hardcoded_group1: List[Tuple[str]]
    hardcoded_group2: List[Tuple[str]]
    hardcoded_interface: str

@dataclass
class DnsConfig:
    domains: List[Tuple[str]]

@dataclass
class Config:
    arp: ArpConfig
    dns: DnsConfig

def _load() -> Config:
    path = Path(__file__).parent / "config.toml"
    with path.open("rb") as f:
        data = tomllib.load(f)

    return Config(
        arp=ArpConfig(**data["arp"]),
        dns=DnsConfig(**data["dns"])
        )

config = _load()