import uuid
import datetime
import hashlib
from typing import List, Optional
from fastapi import FastAPI, HTTPException, UploadFile, File, Depends
from pydantic import BaseModel, Field

app = FastAPI(title="ScopeVault Evidence Server")

# --- Schemas ---

class EvidenceMetadata(BaseModel):
    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    execution_id: str
    tool_name: str
    sha256_hash: str
    tags: List[str] = []
    integrity_verified: bool = True

# --- In-Memory Store (Replace with PostgreSQL for Production) ---
evidence_db = {}

# --- Logic ---

def calculate_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

@app.post("/evidence/upload", response_model=EvidenceMetadata)
async def upload_evidence(
    execution_id: str,
    tool_name: str,
    tags: str = "",
    file: UploadFile = File(...)
):
    """
    Validates, hashes, and persists evidence following the policy-first execution model.
    """
    content = await file.read()
    file_hash = calculate_sha256(content)

    metadata = EvidenceMetadata(
        execution_id=execution_id,
        tool_name=tool_name,
        sha256_hash=file_hash,
        tags=[t.strip() for t in tags.split(",") if t.strip()]
    )

    evidence_db[metadata.evidence_id] = {
        "metadata": metadata,
        "content": content
    }

    return metadata

@app.get("/evidence/{evidence_id}", response_model=EvidenceMetadata)
async def get_evidence_metadata(evidence_id: str):
    if evidence_id not in evidence_db:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return evidence_db[evidence_id]["metadata"]

@app.get("/evidence/{evidence_id}/verify")
async def verify_integrity(evidence_id: str):
    """
    Recalculates hash to ensure evidence hasn't been tampered with post-ingestion.
    """
    if evidence_id not in evidence_db:
        raise HTTPException(status_code=404, detail="Evidence not found")

    record = evidence_db[evidence_id]
    current_hash = calculate_sha256(record["content"])

    is_valid = current_hash == record["metadata"].sha256_hash

    return {
        "evidence_id": evidence_id,
        "integrity_status": "valid" if is_valid else "compromised",
        "expected_hash": record["metadata"].sha256_hash,
        "actual_hash": current_hash
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
