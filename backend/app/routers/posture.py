from fastapi import APIRouter, HTTPException, Depends
import json
import os
from app.schemas.posture import SecurityPosture, CodeFinding
from app.services.reasoning import reasoning_engine

router = APIRouter(tags=["Security Posture"])

def get_demo_posture() -> SecurityPosture:
    data_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "demo_posture.json")
    if not os.path.exists(data_path):
        raise HTTPException(status_code=404, detail="Demo posture data not found. Run generate_fixture.py first.")

    with open(data_path, "r") as f:
        data = json.load(f)
        return SecurityPosture(**data)

@router.get("/posture", response_model=SecurityPosture)
async def get_posture():
    """Returns the aggregated security posture for the demo repository."""
    return get_demo_posture()

@router.get("/findings/{finding_id}", response_model=CodeFinding)
async def get_finding(finding_id: str):
    """Returns a specific finding by ID, augmented with AI reasoning."""
    posture = get_demo_posture()
    for finding in posture.findings:
        if finding.id == finding_id:
            # Run the deterministic finding through the AI reasoning engine
            augmented_finding = await reasoning_engine.analyze_finding(finding)
            return augmented_finding

    raise HTTPException(status_code=404, detail="Finding not found")
