import tomllib
from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple

@dataclass
class DiscoveryConfig:
    automatic_discovery: bool
    skip_discovery: bool
    hardcoded_group1: List[Tuple[str]]
    hardcoded_group2: List[Tuple[str]]
    hardcoded_interface: str

@dataclass
class ArpConfig:
    poison_warm_up: int
    poison_delay: int
    poison_icmp: bool
    poison_reply: bool
    poison_request: bool
    poison_oneway: bool
    dos_enabled: bool

@dataclass
class DnsConfig:
    enabled: bool
    domains: List[Tuple[str]]

@dataclass
class SSLConfig:
    enabled: bool

@dataclass
class Config:
    discovery: DiscoveryConfig
    arp: ArpConfig
    dns: DnsConfig
    ssl: SSLConfig

def _load() -> Config:
    path = Path(__file__).parent / "config.toml"
    with path.open("rb") as f:
        data = tomllib.load(f)

    return Config(
        discovery=DiscoveryConfig(**data["discovery"]),
        arp=ArpConfig(**data["arp"]),
        dns=DnsConfig(**data["dns"]),
        ssl=SSLConfig(**data["ssl"])
        )

config = _load()