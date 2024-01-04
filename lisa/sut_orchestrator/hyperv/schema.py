from dataclasses import dataclass, field
from typing import List, Optional

from dataclasses_json import dataclass_json


@dataclass_json
@dataclass
class HypervServer:
    address: str
    username: str
    password: str


@dataclass_json
@dataclass
class HypervPlatformSchema:
    servers: List[HypervServer] = field(default_factory=list)


@dataclass_json
@dataclass
class HypervNodeSchema:
    hyperv_generation: int = 2
    vhd: str = ""
    # experimental args to be passed to Set-VMProcessor cmdlet
    processor_experimental_args: Optional[str] = None
