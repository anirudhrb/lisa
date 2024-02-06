# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from dataclasses import dataclass, field
from typing import List, Optional

from dataclasses_json import dataclass_json

from lisa import schema
from lisa.util import field_metadata


@dataclass_json
@dataclass
class HypervServer:
    address: str
    username: str
    password: str


@dataclass_json
@dataclass
class ExtraArgs:
    command: str
    args: str


@dataclass_json
@dataclass
class SourceFileSchema:
    source: str = field(default="", metadata=field_metadata(required=True))
    # if destination is not provided by user, the source implementation will decide
    # the destination.
    destination: Optional[str] = None
    unzip: bool = False


@dataclass_json()
@dataclass
class SourceSchema(schema.TypedSchema, schema.ExtendableSchemaMixin):
    files: List[SourceFileSchema] = field(default_factory=list)


@dataclass_json()
@dataclass
class LocalSourceSchema(SourceSchema):
    pass


@dataclass_json
@dataclass
class HypervPlatformSchema:
    source: Optional[SourceSchema] = None
    servers: List[HypervServer] = field(default_factory=list)
    extra_args: List[ExtraArgs] = field(default_factory=list)


@dataclass_json
@dataclass
class VhdSchema(schema.ImageSchema):
    vhd_path: Optional[str] = None


@dataclass_json
@dataclass
class HypervNodeSchema:
    hyperv_generation: int = 2
    vhd: Optional[VhdSchema] = None
    osdisk_size_in_gb: int = 30
