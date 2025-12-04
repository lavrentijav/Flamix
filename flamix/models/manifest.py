"""Модели для manifest.json плагинов"""

from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field, validator
import semantic_version

from flamix.config import API_VERSION


class FirewallVersionRange(BaseModel):
    """Диапазон версий firewall"""
    min: Optional[str] = None
    max: Optional[str] = None
    exact: List[str] = Field(default_factory=list)

    @validator("min", "max", pre=True)
    def validate_version(cls, v):
        if v is None:
            return None
        try:
            semantic_version.Version(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid semantic version: {v}")

    @validator("exact", pre=True)
    def validate_exact_versions(cls, v):
        if not v:
            return []
        for version in v:
            try:
                semantic_version.Version(version)
            except ValueError:
                raise ValueError(f"Invalid semantic version in exact list: {version}")
        return v


class FirewallDetect(BaseModel):
    """Настройки детекта firewall"""
    type: Literal["command", "script"]
    value: str


class FirewallSupport(BaseModel):
    """Поддержка конкретного firewall"""
    name: str
    versions: FirewallVersionRange
    detect: FirewallDetect
    regex: List[str] = Field(..., min_items=1)
    requires_root: bool = True
    priority: int = Field(default=100, ge=0, le=1000)


class PluginDependencies(BaseModel):
    """Зависимости плагина"""
    python: Optional[str] = None
    packages: List[str] = Field(default_factory=list)


class RuleField(BaseModel):
    """Поле в схеме правила"""
    name: str
    type: Literal["text", "number", "select", "radio"]
    label: str
    required: bool = False
    min: Optional[int] = None
    max: Optional[int] = None
    options: List[Dict[str, str]] = Field(default_factory=list)  # For select/radio
    default: Optional[Any] = None


class RuleSchema(BaseModel):
    """Схема для динамических форм правил"""
    fields: List[RuleField]


class PluginManifest(BaseModel):
    """Манифест плагина"""
    id: str = Field(..., pattern=r"^[a-z0-9._-]+$")
    name: str
    version: str
    author: str
    platforms: List[str]
    entry_point: str
    capabilities: List[str]
    permissions: List[str]
    dependencies: PluginDependencies = Field(default_factory=PluginDependencies)
    signature: str = ""  # RSA-SHA256 подпись
    checksum: str = ""  # SHA-256 хеш ZIP
    api_version: str
    firewall_support: List[FirewallSupport] = Field(..., min_items=1)
    rule_schema: Optional[RuleSchema] = None

    @validator("version", pre=True)
    def validate_version(cls, v):
        try:
            semantic_version.Version(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid semantic version: {v}")

    @validator("api_version", pre=True)
    def validate_api_version(cls, v):
        if v != API_VERSION:
            raise ValueError(f"Unsupported API version: {v}, expected {API_VERSION}")
        return v

    class Config:
        extra = "forbid"

