# main.py
import json, os
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import state, planner, fsm

app = FastAPI()
state.init()

@app.post("/v2/incidents")
async def post_incident(req: Request):
    body = await req.json()
    if body.get("profile") != "ga5-incident-agent/v2":
        return JSONResponse({"error":"bad profile"}, status_code=400)
    run_id = body.get("runId")
    existing = state.get_run(run_id)
    if existing:
        if existing["request_hash"] == state.sha({k:v for k,v in body.items() if not k.startswith("_")}):
            return Response(existing["final_json"], media_type="application/json")
        return JSONResponse({"error":"conflict"}, status_code=409)

    # --- single model call ---
    plan = planner.plan(body["incident"], body["toolCatalog"], body["policy"])
    body["_plan"] = plan
    body["_incoming_traceparent"] = req.headers.get("traceparent")
    body.setdefault("model_name", os.environ.get("MODEL_NAME","unknown"))
    resp = fsm.start_run(body)
    return JSONResponse(resp)

@app.post("/v2/incidents/{run_id}/receipts")
async def post_receipt(run_id: str, req: Request):
    body = await req.json()
    out = fsm.handle_receipt(run_id, body)
    if "error" in out:
        return JSONResponse({"error": out["error"]}, status_code=out["code"])
    return JSONResponse(out)

@app.get("/v2/incidents/{run_id}")
async def get_incident(run_id: str):
    run = state.get_run(run_id)
    if not run: return JSONResponse({"error":"not found"}, status_code=404)
    return Response(run["final_json"], media_type="application/json")
