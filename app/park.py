"""What the «Парк» page shows besides raw rows: gate state from the journal, the
health and setup readiness of each route, and the «требует внимания» list — facts
paired with the action that fixes them. Pure read-side helpers, no node calls."""

from __future__ import annotations

from sqlalchemy.orm import Session

from .models import (
    HIST_HUB,
    PROTO_NAIVE,
    GatePool,
    GateSample,
    NaiveCert,
    Node,
    NodeStatusHistory,
    Route,
)


def _when(t) -> str:
    return t.strftime("%d.%m %H:%M") + " UTC" if t else ""


def gate_states(db: Session) -> dict[int, dict]:
    """{gate id: {live, abroad, since, clients}} from the gate journal. `live` =
    the Hub still reaches it (the same rule DNS uses); `abroad` = the last probe
    from abroad (None = no vantage point); `since` = when it went down from RU."""
    from . import journal

    live = journal.live_gate_ids(db)
    out: dict[int, dict] = {}
    for g in db.query(Node).filter(Node.role == "gate").all():
        last = (db.query(GateSample).filter(GateSample.node_id == g.id)
                .order_by(GateSample.at.desc(), GateSample.id.desc()).first())
        since = None
        if g.id not in live:
            flip = (db.query(NodeStatusHistory)
                    .filter(NodeStatusHistory.node_id == g.id, NodeStatusHistory.kind == HIST_HUB,
                            NodeStatusHistory.up.is_(False))
                    .order_by(NodeStatusHistory.at.desc()).first())
            since = flip.at if flip else (last.at if last else None)
        out[g.id] = {
            "live": g.id in live,
            "abroad": last.abroad_ok if last else None,
            "since": _when(since),
            "clients": last.clients if last else None,
            "probed": last is not None,
        }
    return out


def gate_tip(g: Node, st: dict) -> str:
    if not st or not st.get("probed"):
        return f"{g.public_host} · журнал ещё не проверял"
    if st["live"]:
        c = st.get("clients")
        return f"{g.public_host} · отвечает" + (f" · клиентов сейчас: {c}" if c is not None else "")
    tip = f"{g.public_host} · не отвечает из РФ" + (f" с {st['since']}" if st["since"] else "")
    if st.get("abroad"):
        tip += ", из-за рубежа доступен"
    return tip


def certs(db: Session, routes: list[Route]) -> dict[int, NaiveCert | None]:
    """{route protocol id: certificate} for NaiveProxy protocols with a hostname."""
    out = {}
    for r in routes:
        rp = r.proto(PROTO_NAIVE)
        if rp is not None and rp.client_host:
            out[rp.id] = db.get(NaiveCert, rp.client_host.lower())
    return out


def route_health(r: Route, gst: dict[int, dict], crt: dict) -> dict:
    """state: ok | warn | bad | off, plus what's wrong in words."""
    gates = r.gates
    live = [g for g in gates if gst.get(g.id, {}).get("live", True)]
    servers = r.pool.members if r.pool else []
    deployed = [s for s in servers if s.sync_state == "synced"]
    probs: list[str] = []
    if r.pool is None:
        probs.append("нет пула выходов")
    if not r.is_direct and not gates:
        probs.append("в пуле гейтов нет гейтов")
    elif not r.is_direct and not live:
        probs.append("вход недоступен из РФ — ни один гейт пула не отвечает")
    if r.pool is not None and not deployed:
        probs.append("нет развёрнутых выходов")
    if not r.protos:
        probs.append("не включён ни один протокол")
    elif not r.active_protocols:
        probs.append("все протоколы на паузе")
    for rp in r.protos_sorted:
        if rp.enabled and rp.protocol == PROTO_NAIVE:
            if not rp.client_host:
                probs.append("у NaiveProxy не задано имя хоста")
            elif not crt.get(rp.id):
                probs.append("NaiveProxy без сертификата")
    if not r.groups:
        probs.append("доступ никому не открыт")
    hard = (r.pool is None or (not r.is_direct and not live) or (r.pool is not None and not deployed)
            or not r.active_protocols)
    state = "off" if not r.enabled else ("bad" if hard else ("warn" if probs else "ok"))
    return {"state": state, "probs": probs, "live": len(live), "gates": len(gates),
            "deployed": len(deployed), "servers": len(servers)}


def readiness(r: Route, crt: dict, relay_problem: str) -> list[dict]:
    """The route's setup sequence, each step done or not, with what's left."""
    servers = r.pool.members if r.pool else []
    deployed = [s for s in servers if s.sync_state == "synced"]
    steps = [
        {"t": "Серверы в пуле выходов", "ok": bool(servers),
         "d": f"{len(servers)} в пуле «{r.pool.name}»" if r.pool else "пул не выбран"},
        {"t": "Серверы развёрнуты", "ok": bool(servers) and len(deployed) == len(servers),
         "d": f"{len(deployed)} из {len(servers)}" + (" — «Применить» доставит недостающее"
                                                      if len(deployed) < len(servers) else "")},
    ]
    if r.is_direct:
        steps.append({"t": "Вход", "ok": True, "d": "напрямую — клиенты идут на серверы пула"})
    else:
        steps.append({"t": "Гейты в пуле, релей собирается", "ok": bool(r.gates) and not relay_problem,
                      "d": relay_problem or f"{len(r.gates)} гейт. в пуле «{r.gate_pool.name}»"})
    act = [rp for rp in r.protos_sorted if rp.enabled]
    steps.append({"t": "Включён протокол", "ok": bool(act),
                  "d": ", ".join(rp.label for rp in act) or "все выключены"})
    addr_ok = all(rp.client_host or rp.protocol != PROTO_NAIVE for rp in act)
    steps.append({"t": "Адреса протоколов", "ok": addr_ok,
                  "d": " · ".join(f"{rp.label}: {rp.client_host or 'IP первого входа'}" for rp in act) or "—"})
    nrp = r.proto(PROTO_NAIVE)
    if nrp is not None and nrp.enabled:
        c = crt.get(nrp.id)
        steps.append({"t": "Сертификат NaiveProxy", "ok": bool(c),
                      "d": f"до {c.not_after.strftime('%d.%m.%Y')}" if c else "не выпущен — нужен до «Применить»"})
    steps.append({"t": "Доступ групп", "ok": bool(r.groups),
                  "d": ", ".join(g.name for g in r.groups) or "никому — клиенты маршрут не видят"})
    return steps


def attention(routes: list[Route], gate_pools: list[GatePool], orphans: list[Node],
              gst: dict[int, dict], crt: dict, cert_busy: set[int] | None = None) -> list[dict]:
    """[{sev, name, text, detail, actions: [{label, post|open|tab}]}] — most severe
    first. Every item names what's wrong and offers the action that fixes it."""
    out: list[dict] = []
    for gp in gate_pools:
        users = [r.name for r in gp.routes]
        for g in gp.gates:
            st = gst.get(g.id) or {}
            if not st.get("probed") or st.get("live"):
                continue
            others = len(gp.gates) - 1
            out.append({
                "sev": "bad", "name": g.name,
                "text": "не отвечает из РФ" + (f" с {st['since']}" if st["since"] else "")
                        + (", из-за рубежа доступен — похоже на блокировку" if st.get("abroad") else ""),
                "detail": (f"Маршруты: {', '.join(users)} — " if users else "Пул не используется — ")
                          + (f"работают через остальные гейты пула ({others})" if others
                             else f"других гейтов в пуле «{gp.name}» нет"),
                "actions": [{"label": f"Добавить гейт в «{gp.name}»", "tab": "servers"},
                            {"label": "Журнал", "href": "/admin/journal"}],
            })
    for r in routes:
        if not r.enabled:
            continue
        nrp = r.proto(PROTO_NAIVE)
        if nrp is not None and nrp.enabled:
            if not nrp.client_host:
                out.append({"sev": "warn", "name": r.name, "text": "у NaiveProxy не задано имя хоста",
                            "detail": "На него выпускается сертификат", "actions": [{"label": "Открыть маршрут", "open": r.id}]})
            elif not crt.get(nrp.id):
                busy = nrp.id in (cert_busy or set())
                out.append({"sev": "warn", "name": r.name,
                            "text": f"{'выпускается' if busy else 'нет'} сертификат для {nrp.client_host}",
                            "detail": "Займёт 1–2 минуты, страница обновится сама" if busy
                                      else "Без него NaiveProxy на серверах не запустить",
                            "actions": [] if busy else
                                       [{"label": "Выпустить сертификат", "post": f"/admin/routes/{r.id}/cert"}]})
        for s in (r.pool.members if r.pool else []):
            if s.sync_state != "synced" and not s.job_running:
                what = "недоступен" if s.sync_state == "unreachable" else "не развёрнут"
                out.append({"sev": "warn", "name": s.name, "text": f"в пуле «{r.pool.name}» {what}",
                            "detail": f"Маршрут «{r.name}»" + (f" · {s.job_message[:120]}" if s.job_state == "error" and s.job_message else ""),
                            "actions": [{"label": f"Применить «{r.name}»", "post": f"/admin/routes/{r.id}/apply"}]})
        if not r.groups:
            out.append({"sev": "warn", "name": r.name, "text": "доступ никому не открыт",
                        "detail": "Клиенты не видят маршрут; персонал — видит",
                        "actions": [{"label": "Открыть маршрут", "open": r.id}]})
    if orphans:
        out.append({"sev": "warn", "name": "", "text": f"Серверов не в пулах: {len(orphans)}",
                    "detail": ", ".join(n.name for n in orphans),
                    "actions": [{"label": "Разложить по пулам", "tab": "servers"}]})
    out.sort(key=lambda x: 0 if x["sev"] == "bad" else 1)
    return out
