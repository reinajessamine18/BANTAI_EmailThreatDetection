from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, StrictBool


class ProfileUpdate(BaseModel):
    """PATCH /account/profile. Only the fields you send are changed; null clears jobTitle/profilePicture."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    full_name: Optional[str] = Field(default=None, alias="fullName", max_length=200)
    job_title: Optional[str] = Field(default=None, alias="jobTitle", max_length=200)
    profile_picture: Optional[str] = Field(default=None, alias="profilePicture", max_length=400000)
    email: Optional[str] = Field(default=None, max_length=254)
    current_password: Optional[str] = Field(default=None, alias="currentPassword", max_length=128)


class PasswordChange(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    current_password: str = Field(alias="currentPassword", min_length=1, max_length=128)
    new_password: str = Field(alias="newPassword", min_length=10, max_length=128)


class PreferencesUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    shap_advanced_mode: Optional[StrictBool] = Field(default=None, alias="shapAdvancedMode")
    auto_save_scan_logs: Optional[StrictBool] = Field(default=None, alias="autoSaveScanLogs")
