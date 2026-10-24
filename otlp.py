# otlp.py
import json, uuid

def _span(state, name, kind, parent_id, **attrs):
    return {"traceId": state["trace_id"], "spanId": uuid.uuid4().hex[:16],
            "parentSpanId": parent_id, "name": name, "kind": kind,
            "attributes": [{"key":k,"value":{"stringValue":str(v)}} for k,v in
                           {"ga5.run.id": state["run_id"],
                            "ga5.public.marker": state["publicMarker"], **attrs}.items()]}

def build_otlp(state):
    trace = state["trace_id"]
    server = _span(state, "POST /v2/incidents", 2, "")
    server["traceId"] = trace
    agent  = _span(state, "invoke_agent incident-response", 1, server["spanId"])
    agent["attributes"].append({"key":"gen_ai.operation.name","value":{"stringValue":"invoke_agent"}})

    chat = _span(state, "chat incident-plan", 3, agent["spanId"])
    chat["attributes"].append({"key":"gen_ai.operation.name","value":{"stringValue":"chat"}})
    chat["attributes"].append({"key":"gen_ai.request.model","value":{"stringValue":state.get("model_name","unknown")}})

    spans = [server, agent, chat]
    tool_spans = {}  # actionId -> execute_tool span id

    # logical actions: one execute_tool per unique actionId
    seen = set()
    for a in state["actionLog"]:
        if a["actionId"] in seen: continue
        seen.add(a["actionId"])
        ts = _span(state, f"execute_tool {a['toolName']}", 1, agent["spanId"],
                   **{"ga5.action.id": a["actionId"],
                      "gen_ai.tool.name": a["toolName"],
                      "gen_ai.tool.call.id": a["callId"],
                      "gen_ai.operation.name": "execute_tool"})
        tool_spans[a["actionId"]] = ts["spanId"]
        spans.append(ts)

    # physical attempts: one CLIENT per actionLog entry, correlated to receipt
    receipt_by = {}
    for r in state["receiptLog"]:
        if "callId" in r:
            receipt_by[(r["callId"], r["attempt"])] = r
    for a in state["actionLog"]:
        r = receipt_by.get((a["callId"], a["attempt"]))
        cs = _span(state, f"POST tool/{a['toolName']}", 3, tool_spans[a["actionId"]],
                   **{"ga5.action.id": a["actionId"],
                      "ga5.attempt": a["attempt"],
                      "ga5.receipt.id": r["receiptId"] if r else "",
                      "ga5.receipt.nonce": r["nonce"] if r else "",
                      "http.request.method": "POST",
                      "http.request.resend_count": a["attempt"]-1})
        if r:
            if r["status"] == 503:
                cs["status"] = {"code": 2}
                cs["attributes"].append({"key":"error.type","value":{"stringValue":"503"}})
            elif r["status"] == 0:
                cs["status"] = {"code": 2}
                cs["attributes"].append({"key":"error.type","value":{"stringValue":"timeout"}})
        spans.append(cs)

    # join (diagnostics fan-out)
    diag = [a for a in state["actionLog"] if a["phase"]=="diagnostic"]
    if len({a["actionId"] for a in diag}) > 1:
        js = _span(state, "incident.join", 1, agent["spanId"])
        js["links"] = [{"traceId": trace, "spanId": tool_spans[a["actionId"]]}
                       for a in diag]
        spans.append(js)

    # approval gate
    for r in state["receiptLog"]:
        if "approvalId" in r:
            ag = _span(state, "approval_gate", 1, agent["spanId"],
                       **{"ga5.approval.id": r["approvalId"],
                          "ga5.receipt.nonce": r["nonce"]})
            spans.append(ag)

    return {"resourceSpans":[{"scopeSpans":[{"spans": spans}]}]}
