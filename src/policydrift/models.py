from typing import Literal

from pydantic import BaseModel


class Policy(BaseModel):
    id: str
    description: str
    category: str
    severity: Literal["low", "medium", "high"]


class Finding(BaseModel):
    file_path: str
    line_number: int
    line_content: str
    policy_id: str
    explanation: str
    suggested_fix: str
    confidence: float


class ScanReport(BaseModel):
    findings: list[Finding]
    files_scanned: int
    policies_checked: int
