from pydantic import BaseModel, Field

class ScanMetadata(BaseModel):
    """
    Contextual information about the current scan passed to rules.
    """
    scan_id: str = "unknown"
    target_url: str = ""
    scan_type: str = "url"
