from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

# base64 inflates by 4/3, so a 5 MB .eml is about 6.7 million characters.
MAX_CONTENT_CHARS = 7_500_000


class ScanRequest(BaseModel):
    """Body of POST /scans. camelCase (as the React app sends it); snake_case also accepted.

    Unknown fields are rejected, so a typo or injected field fails loudly.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    input_method: Literal["eml_upload", "raw_text"] = Field(alias="inputMethod")
    content: str = Field(min_length=1, max_length=MAX_CONTENT_CHARS)
    encoding: Literal["text", "base64"] = "text"
    file_name: Optional[str] = Field(default=None, alias="fileName", max_length=255)
