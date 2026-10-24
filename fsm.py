# fsm.py
import uuid, hashlib, json
from state import sha, get_run, get_receipt, tx

def new_id() -> str:
    return uuid.uuid4().hex  # 32 hex chars, opaque, >=8

def new_trace_context(incoming=None):
    """Return (traceparent_out, tracestate_out, trace_id)."""
    if incoming and re_valid_traceparent(incoming):
        tp = incoming.strip()
        parts = tp.split("-")
        trace_id = parts[1]
        # continue trace; caller supplies CLIENT span id per dispatch
        return trace_id, None
    trace_id = uuid.uuid4().hex  # 32 hex
    return trace_id, None

def re_valid_traceparent(tp):
    return bool(tp and len(tp.split("-")) == 4 and tp.split("-")[0] == "00"
                and len(tp.split("-")[1]) == 32 and tp.split("-")[1] != "0"*32)

def make_traceparent(trace_id, span_id):
    return f"00-{trace_id}-{span_id}-01"

def arguments_digest(args) -> str:
    return hashlib.sha256(
        json.dumps(args, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

def start_run(body: dict) -> dict:
    """Called by POST /v2/incidents (first time)."""
    run_id = body["runId"]
    # planner call happens in route; here we receive the plan dict
    plan = body["_plan"]
    trace_id, _ = new_trace_context(body.get("_incoming_traceparent"))

    dispatches = []
    for i, d in enumerate(plan["dispatches"]):
        action_id = new_id()
        call_id   = new_id()
        span_id   = new_id()[:16]
        dispatches.append({
            "actionId": action_id, "callId": call_id,
            "phase": "diagnostic", "toolName": d["toolName"],
            "arguments": d["arguments"], "evidence": d["evidence"],
            "attempt": 1,
            "traceparent": make_traceparent(trace_id, span_id),
        })

    state = {
        "phase": "WAIT_DIAG",
        "trace_id": trace_id,
        "diagnosis": {"rootCause": plan["rootCause"], "evidence": plan["evidence"]},
        "dispatches": dispatches,
        "pending": {d["callId"]: d for d in dispatches},
        "actionLog": [],
        "receiptLog": [],
        "approvals": [],
        "effect": None,
        "toolCatalog": body["toolCatalog"],
        "policy": body["policy"],
        "publicMarker": body["publicMarker"],
        "agentName": body["agentName"],
    }
    state["actionLog"] = [dict(d) for d in dispatches]

    resp = {"runId": run_id, "status": "waiting",
            "diagnosis": state["diagnosis"],
            "dispatches": dispatches, "approvals": []}
    _persist(run_id, body, state, resp)
    return resp

def handle_receipt(run_id, receipt: dict) -> dict:
    run = get_run(run_id)
    if not run: return {"error": "unknown run", "code": 404}
    if run["status"] != "waiting":
        # replay identical receipt -> same response
        r = get_receipt(run_id, receipt["receiptId"])
        if r and r["receipt_hash"] == sha(receipt):
            return json.loads(r["response_json"])
        return {"error": "conflict", "code": 409}

    existing = get_receipt(run_id, receipt["receiptId"])
    if existing:
        if existing["receipt_hash"] == sha(receipt):
            return json.loads(existing["response_json"])
        return {"error": "conflict", "code": 409}

    state = json.loads(run["state_json"])
    resp = _advance(state, receipt)

    # persist state + receipt atomically
    with tx() as c:
        c.execute("UPDATE runs SET state_json=?, final_json=?, status=? WHERE run_id=?",
                  (json.dumps(state), json.dumps(resp), resp["status"], run_id))
        c.execute("INSERT INTO receipts VALUES (?,?,?,?,?)",
                  (run_id, receipt["receiptId"], sha(receipt),
                   json.dumps(receipt), json.dumps(resp)))
    return resp

def _advance(state, receipt):
    # --- approval receipt? ---
    if "approvals" in receipt:
        return _handle_approval(state, receipt)
    # --- tool outcomes ---
    for o in receipt["outcomes"]:
        d = state["pending"].get(o["callId"])
        if not d or d["actionId"] != o["actionId"] or d["attempt"] != o["attempt"]:
            continue  # ignore stale/unknown
        state["receiptLog"].append({
            "receiptId": receipt["receiptId"], "actionId": o["actionId"],
            "callId": o["callId"], "attempt": o["attempt"],
            "status": o["status"], "resultClass": o.get("resultClass"),
            "nonce": o["nonce"],
        })
        if o["status"] == 503 and d["attempt"] == 1:
            _retry_dispatch(state, d)
            continue
        if o["status"] == 0 and o.get("errorType") == "timeout":
            state["phase"] = "FAILED"
            state["suppressed"].append({"toolName": d["toolName"], "reason": "timeout"})
            continue
        # success
        del state["pending"][o["callId"]]

    if state["phase"] == "FAILED":
        return _finalize(state)

    if state["pending"]:
        return {"runId": state["run_id"], "status": "waiting",
                "diagnosis": state["diagnosis"],
                "dispatches": list(state["pending"].values()),
                "approvals": state["approvals"]}

    # diagnostics done -> choose effect
    return _choose_effect(state, receipt)

def _retry_dispatch(state, d):
    retry = dict(d)
    retry["attempt"] = d["attempt"] + 1
    retry["traceparent"] = make_traceparent(state["trace_id"], new_id()[:16])
    state["actionLog"].append(dict(retry))
    state["pending"][retry["callId"]] = retry

def _choose_effect(state, receipt):
    cat = {t["name"]: t for t in state["toolCatalog"]}
    effect_tools = state["policy"]["effectTools"]
    # pick exactly one justified effect. For scaling incident -> scale_service.
    # Heuristic: choose the non-destructive effect whose schema fits; fall back to first.
    target = next((t for t in effect_tools if t not in state["policy"]["approvalRequiredFor"]),
                  effect_tools[0])
    args = {}  # fill from incident-specific values; see incident fields
    action_id = new_id(); call_id = new_id()
    if target in state["policy"]["approvalRequiredFor"]:
        approval = {"approvalId": new_id(), "actionId": action_id,
                    "toolName": target, "argumentsDigest": arguments_digest(args)}
        state["approvals"] = [approval]
        state["effect"] = {"actionId": action_id, "callId": call_id,
                           "toolName": target, "arguments": args}
        state["phase"] = "WAIT_APPROVAL"
        return {"runId": state["run_id"], "status": "waiting",
                "diagnosis": state["diagnosis"],
                "dispatches": [], "approvals": [approval]}
    # non-destructive effect -> dispatch directly
    return _dispatch_effect(state, action_id, call_id, target, args)

def _handle_approval(state, receipt):
    a = receipt["approvals"][0]
    state["receiptLog"].append({
        "receiptId": receipt["receiptId"], "approvalId": a["approvalId"],
        "decision": a["decision"], "nonce": a["nonce"],
    })
    if a["decision"] != "approved":
        state["phase"] = "FAILED"
        return _finalize(state)
    eff = state["effect"]
    disp = _dispatch_effect(state, eff["actionId"], eff["callId"],
                            eff["toolName"], eff["arguments"],
                            approvalId=a["approvalId"], approvalNonce=a["nonce"])
    return disp

def _dispatch_effect(state, action_id, call_id, tool, args, **extra):
    d = {"actionId": action_id, "callId": call_id, "phase": "effect",
         "toolName": tool, "arguments": args, "evidence": [],
         "attempt": 1,
         "traceparent": make_traceparent(state["trace_id"], new_id()[:16]),
         **extra}
    state["actionLog"].append(dict(d))
    state["pending"][call_id] = d
    state["phase"] = "WAIT_EFFECT"
    return {"runId": state["run_id"], "status": "waiting",
            "diagnosis": state["diagnosis"],
            "dispatches": [d], "approvals": []}

def _finalize(state):
    state["phase"] = "COMPLETE" if state["phase"] != "FAILED" else "FAILED"
    # Build OTLP from stored state
    from otlp import build_otlp
    otlp = build_otlp(state)
    final = {
        "runId": state["run_id"],
        "status": "completed" if state["phase"] == "COMPLETE" else "failed",
        "diagnosis": state["diagnosis"],
        "chosenEffect": state.get("chosenEffect"),
        "suppressed": state.get("suppressed", []),
        "actionLog": state["actionLog"],
        "receiptLog": state["receiptLog"],
        "otlp": otlp,
    }
    return final

def _persist(run_id, body, state, resp):
    state["run_id"] = run_id
    with tx() as c:
        c.execute("INSERT INTO runs VALUES (?,?,?,?,?,?)",
                  (run_id, sha({k:v for k,v in body.items() if not k.startswith("_")}),
                   json.dumps({k:v for k,v in body.items() if not k.startswith("_")}),
                   json.dumps(state), json.dumps(resp), "waiting"))
