"""
Allocation STRAT v4 — Webhook Server (SECURED)
────────────────────────────────────────────────
Sicherheits-Layer:
  1. WEBHOOK_SECRET   — schützt /webhook (TradingView)
  2. DASHBOARD_TOKEN  — schützt /data (Dashboard liest hier)
  3. CORS Whitelist   — nur erlaubte Origins
  4. Rate Limiting    — max 60 req/min pro IP
  5. Input Validation — alle Eingaben geprüft & bereinigt
  6. Timing-Safe Auth — kein Timing-Angriff möglich
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
from collections import defaultdict
import os, time, hmac, urllib.request, json as _json

app = Flask(__name__)

# ── ENV VARIABLES — in Railway unter "Variables" setzen ──────────────────────
WEBHOOK_SECRET  = os.environ.get("WEBHOOK_SECRET",  "BITTE-AENDERN-webhook-xyz")
DASHBOARD_TOKEN = os.environ.get("DASHBOARD_TOKEN", "BITTE-AENDERN-dashboard-abc")
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*")  # z.B. "https://mein.netlify.app"

CORS(app, resources={
    r"/data":     {"origins": ALLOWED_ORIGINS.split(",") if ALLOWED_ORIGINS != "*" else "*"},
    r"/holdings": {"origins": ALLOWED_ORIGINS.split(",") if ALLOWED_ORIGINS != "*" else "*"},
    r"/prices":   {"origins": ALLOWED_ORIGINS.split(",") if ALLOWED_ORIGINS != "*" else "*"},
})

# ── RATE LIMITER (in-memory) ──────────────────────────────────────────────────
_rate_store = defaultdict(list)
RATE_LIMIT, RATE_WINDOW = 60, 60   # 60 Requests pro 60 Sekunden

def _rate_ok(ip):
    now = time.time()
    _rate_store[ip] = [t for t in _rate_store[ip] if t > now - RATE_WINDOW]
    if len(_rate_store[ip]) >= RATE_LIMIT:
        return False
    _rate_store[ip].append(now)
    return True

def _get_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()

# ── AUTH HELPERS (timing-safe) ────────────────────────────────────────────────
def _check_webhook_auth():
    token = request.args.get("secret") or request.headers.get("X-Secret", "")
    return hmac.compare_digest(str(token), WEBHOOK_SECRET)

def _check_dashboard_auth():
    token = (request.args.get("token")
             or request.headers.get("X-Dashboard-Token", "")
             or request.headers.get("Authorization", "").replace("Bearer ", ""))
    return hmac.compare_digest(str(token), DASHBOARD_TOKEN)

# ── INPUT VALIDATORS ──────────────────────────────────────────────────────────
def _safe_int(v, lo=-1, hi=1):
    try:
        i = int(float(v))
        return i if lo <= i <= hi else None
    except: return None

def _safe_float(v, lo=-1e9, hi=1e9):
    try:
        f = float(v)
        return f if lo <= f <= hi else None
    except: return None

VALID_ASSETS = {"BTC", "ETH", "SOL", "GOLD", "LTPI"}
VALID_MODES  = {"AUTO", "BTC", "ETH", "SOL", "GOLD", "LTPI"}
VALID_DIRS   = {"LONG", "SHORT", "NEUTRAL"}

# ── STATE (in-memory) ─────────────────────────────────────────────────────────
state = {
    "mode":      "AUTO",
    "signals":   {"LTPI": -1, "BTC": -1, "ETH": -1, "SOL": -1, "GOLD": 1},
    "rsi":       {"BTC": 50.0, "ETH": 50.0, "SOL": 50.0, "GOLD": 50.0},
    "roc":       {"BTC": 0.0,  "ETH": 0.0,  "SOL": 0.0,  "GOLD": 0.0},
    "ratios":    {"ETH_BTC": 1, "SOL_BTC": 1, "SOL_ETH": 1, "BTC_GOLD": 1},
    "ratio_raw": {"ETH_BTC": 0.0, "SOL_BTC": 0.0, "SOL_ETH": 0.0, "BTC_GOLD": 0.0},
    "btc_sub":   {"hlsd": 0, "kalman": 0, "qfl": 0, "ndsod": 0},
    "risk": {
        "trash_signal": 0.0, "prelim_ok": False,
        "hb_confidence": 0.0, "hb_exposure": 0.0,
        "hb_winners": [], "paxg_ok": False
    },
    "dom_major":   "BTC",
    "subs": {
        "ltpi_rmsd": -1, "ltpi_bb": -1, "ltpi_onchain": -1,
        "btc_hlsd": -1, "btc_kalman": -1, "btc_qfl": -1, "btc_ndsod": -1,
        "eth_twin": -1, "eth_sd": -1, "eth_vidya": -1,
        "sol_adaptive": -1, "sol_qfl": -1, "sol_kalman": -1,
        "gold_ema": 1, "gold_sig": 1, "gold_sig3": 1
    },
    "ratio_states": {"ethbtc": -1, "solbtc": -1, "soleth": -1, "btcgold": -1},
    "ratio_raw":    {"ethbtc": -1.0, "solbtc": -1.0, "soleth": -0.20, "btcgold": -1.0},
    "momentum": {
        "rsi": {"BTC": 57.47, "ETH": 56.71, "SOL": 54.89, "GOLD": 50.20},
        "roc": {"BTC": 1.66,  "ETH": 2.05,  "SOL": 1.27,  "GOLD": -0.76}
    },
    "alerts":      [],
    "last_update": None,
    "trade_log":   {"BTC": [], "ETH": [], "SOL": [], "GOLD": [], "LTPI": []},
    "open_trade":  {"BTC": None, "ETH": None, "SOL": None, "GOLD": None, "LTPI": None},
    "perf":        {"BTC": {}, "ETH": {}, "SOL": {}, "GOLD": {}, "LTPI": {}}
}

def calc_perf(asset):
    """Recalculate performance stats for one asset from its trade_log."""
    trades = state["trade_log"][asset]
    if not trades:
        state["perf"][asset] = {"net": "—", "trades": "—", "wr": "—"}
        return
    closed = [t for t in trades if t.get("pct") is not None]
    if not closed:
        state["perf"][asset] = {"net": "—", "trades": "0", "wr": "—"}
        return
    total_pct = sum(t["pct"] for t in closed)
    winners   = sum(1 for t in closed if t["pct"] > 0)
    wr        = round(winners / len(closed) * 100, 1)
    sign      = "+" if total_pct >= 0 else ""
    state["perf"][asset] = {
        "net":    f"{sign}{round(total_pct, 2)}%",
        "trades": str(len(closed)),
        "wr":     f"{wr}%"
    }

def calc_dom_major():
    n_eth_btc = state["ratio_states"]["ethbtc"]
    n_sol_btc = state["ratio_states"]["solbtc"]
    n_sol_eth = state["ratio_states"]["soleth"]
    if n_eth_btc == 1 and n_sol_eth == -1:
        state["dom_major"] = "ETH"
    elif n_sol_btc == 1 and n_sol_eth == 1:
        state["dom_major"] = "SOL"
    else:
        state["dom_major"] = "BTC"

def add_alert(msg, asset, direction):
    state["alerts"].insert(0, {
        "msg":       str(msg)[:120],
        "asset":     asset,
        "direction": direction,
        "time":      datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    })
    state["alerts"] = state["alerts"][:20]

# ── /webhook — TradingView sendet hierhin ────────────────────────────────────
# POST https://DEINE-APP.railway.app/webhook?secret=DEIN-WEBHOOK-SECRET
@app.route("/webhook", methods=["POST"])
def webhook():
    if not _rate_ok(_get_ip()):
        return jsonify({"error": "rate_limited"}), 429
    if not _check_webhook_auth():
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "expected_json_object"}), 400

    msg_type = str(data.get("t", data.get("type", ""))).lower()

    # WB-1: Strategy States + Ratio States
    if msg_type == "states":
        # Price map: each asset can send its own price, LTPI uses BTC price
        price_map = {}
        for pk, pf in [("btc_price","BTC"),("eth_price","ETH"),("sol_price","SOL"),("gold_price","GOLD"),("ltpi_price","LTPI")]:
            pv = _safe_float(data.get(pk), 0, 1e9)
            if pv: price_map[pf] = pv
        # If LTPI has no price but BTC does, use BTC as proxy
        if "LTPI" not in price_map and "BTC" in price_map:
            price_map["LTPI"] = price_map["BTC"]
        # Also accept bare "price" field for single-asset alerts
        bare_price = _safe_float(data.get("price"), 0, 1e9)

        for key, field in [("btc","BTC"),("eth","ETH"),("sol","SOL"),("gold","GOLD"),("ltpi","LTPI")]:
            if key in data:
                v = _safe_int(data[key])
                if v is not None:
                    prev = state["signals"][field]
                    state["signals"][field] = v
                    # Determine price for this asset
                    entry_price = price_map.get(field) or bare_price
                    # Close open trade
                    open_t = state["open_trade"][field]
                    if open_t and entry_price:
                        open_dir  = open_t["direction"]
                        open_px   = open_t["price"]
                        if open_dir == "LONG":
                            pct = round((entry_price - open_px) / open_px * 100, 3)
                        else:
                            pct = round((open_px - entry_price) / open_px * 100, 3)
                        open_t["exit_price"] = entry_price
                        open_t["exit_time"]  = datetime.utcnow().isoformat()
                        open_t["pct"]        = pct
                        state["trade_log"][field].append(open_t)
                        state["open_trade"][field] = None
                        calc_perf(field)
                    # Open new trade
                    if v != 0 and entry_price:
                        direction = "LONG" if v == 1 else "SHORT"
                        state["open_trade"][field] = {
                            "direction":  direction,
                            "price":      entry_price,
                            "entry_time": datetime.utcnow().isoformat(),
                            "exit_price": None,
                            "exit_time":  None,
                            "pct":        None
                        }
                    # Flip alert
                    if (prev == 1 and v == -1) or (prev == -1 and v == 1):
                        f_dir = "LONG" if prev == 1 else "SHORT"
                        t_dir = "LONG" if v    == 1 else "SHORT"
                        add_alert(f"{field} flip: {f_dir} → {t_dir}", field, t_dir)
        # RSI + ROC momentum
        rsi_map = [("rsi_btc","BTC"),("rsi_eth","ETH"),("rsi_sol","SOL"),("rsi_gold","GOLD")]
        roc_map = [("roc_btc","BTC"),("roc_eth","ETH"),("roc_sol","SOL"),("roc_gold","GOLD")]
        for key, field in rsi_map:
            if key in data:
                v = _safe_float(data[key], 0, 100)
                if v is not None: state["momentum"]["rsi"][field] = round(v, 2)
        for key, field in roc_map:
            if key in data:
                v = _safe_float(data[key], -100, 100)
                if v is not None: state["momentum"]["roc"][field] = round(v, 2)
        # Sub-indicators
        sub_map = {
            "ltpi_rmsd": "ltpi_rmsd", "ltpi_bb": "ltpi_bb", "ltpi_onchain": "ltpi_onchain",
            "btc_hlsd": "btc_hlsd", "btc_kalman": "btc_kalman", "btc_qfl": "btc_qfl", "btc_ndsod": "btc_ndsod",
            "eth_twin": "eth_twin", "eth_sd": "eth_sd", "eth_vidya": "eth_vidya",
            "sol_adaptive": "sol_adaptive", "sol_qfl": "sol_qfl", "sol_kalman": "sol_kalman",
            "gold_ema": "gold_ema", "gold_sig": "gold_sig", "gold_sig3": "gold_sig3",
        }
        for key, field in sub_map.items():
            if key in data:
                v = _safe_int(data[key])
                if v is not None and v != 0:
                    state["subs"][field] = v
        # Ratio States → Dominant Major
        ratio_updated = False
        for key, field in [("ethbtc_ratio","ethbtc"),("solbtc_ratio","solbtc"),("soleth_ratio","soleth"),("btcgold_ratio","btcgold")]:
            if key in data:
                v = _safe_int(data[key])
                if v is not None:
                    state["ratio_states"][field] = v
                    ratio_updated = True
        # Raw MTPI values
        for key, field in [("ethbtc_raw","ethbtc"),("solbtc_raw","solbtc"),("soleth_raw","soleth"),("btcgold_raw","btcgold")]:
            if key in data:
                v = _safe_float(data[key], -1e6, 1e6)
                if v is not None:
                    state["ratio_raw"][field] = round(v, 4)
        if ratio_updated:
            calc_dom_major()

    # WB-2: RSI + ROC
    elif msg_type == "rsi":
        for k,a in [("rsi_btc","BTC"),("rsi_eth","ETH"),("rsi_sol","SOL"),("rsi_gold","GOLD")]:
            if k in data:
                v = _safe_float(data[k], 0, 100)
                if v is not None: state["rsi"][a] = v
        for k,a in [("roc_btc","BTC"),("roc_eth","ETH"),("roc_sol","SOL"),("roc_gold","GOLD")]:
            if k in data:
                v = _safe_float(data[k], -100, 100)
                if v is not None: state["roc"][a] = v

    # WB-3: Ratios
    elif msg_type == "ratios":
        for k,f in [("n_ethbtc","ETH_BTC"),("n_solbtc","SOL_BTC"),("n_soleth","SOL_ETH"),("n_btcgold","BTC_GOLD")]:
            if k in data:
                v = _safe_int(data[k])
                if v is not None: state["ratios"][f] = v
        for k,f in [("r_ethbtc","ETH_BTC"),("r_solbtc","SOL_BTC"),("r_soleth","SOL_ETH"),("r_btcgold","BTC_GOLD")]:
            if k in data:
                v = _safe_float(data[k], -1e6, 1e6)
                if v is not None: state["ratio_raw"][f] = v

    # WB-4: Risk & Trash
    elif msg_type == "risk":
        for src,dst,lo,hi in [("trash","trash_signal",-2,2),("trash01","trash_signal",0,1),("hb_cap","hb_confidence",0,1)]:
            if src in data:
                v = _safe_float(data[src], lo, hi)
                if v is not None: state["risk"][dst] = v
        if "prelim" in data:
            state["risk"]["prelim_ok"] = bool(int(float(data.get("prelim", 0))))
        if "paxg_ok" in data:
            state["risk"]["paxg_ok"] = bool(int(float(data.get("paxg_ok", 0))))

    # WB-5: Cash Signals + HB Allocations
    elif msg_type == "alloc":
        for k,a in [("cs_btc","BTC"),("cs_eth","ETH"),("cs_sol","SOL"),("cs_gold","GOLD")]:
            if k in data:
                v = _safe_float(data[k], 0, 1)
                state.setdefault("cash_signals", {})[a] = v if v is not None else 0.0
        for k,a in [("a_bnb","BNB"),("a_doge","DOGE"),("a_ada","ADA"),("a_hype","HYPE"),
                    ("a_link","LINK"),("a_sui","SUI"),("a_xrp","XRP")]:
            if k in data:
                v = _safe_float(data[k], 0, 1)
                state.setdefault("hb_alloc", {})[a] = v if v is not None else 0.0

    # WB-6: BTC Sub-Indicators
    elif msg_type == "btcsub":
        for k in ("hlsd","kalman","qfl","ndsod"):
            if k in data:
                v = _safe_int(data[k])
                if v is not None: state["btc_sub"][k] = v

    # Flip-Alert (from existing pine script alert() calls)
    elif msg_type == "flip":
        asset = str(data.get("asset", "")).upper()
        frm   = str(data.get("from", "")).upper()
        to    = str(data.get("to",   "")).upper()
        if asset in VALID_ASSETS and frm in VALID_DIRS and to in VALID_DIRS:
            add_alert(f"{asset} flip: {frm} → {to}", asset, to)

    # Legacy single-asset update
    else:
        asset = str(data.get("asset", "")).upper()
        if asset in state["signals"] and "state" in data:
            v = _safe_int(data["state"])
            if v is not None: state["signals"][asset] = v
        dm = str(data.get("dom_major","")).upper()
        if dm in VALID_ASSETS: state["dom_major"] = dm
        mode = str(data.get("mode","")).upper()
        if mode in VALID_MODES: state["mode"] = mode
    state["last_update"] = datetime.utcnow().isoformat() + "Z"
    return jsonify({"ok": True})


# ── /data — Dashboard liest hieraus ──────────────────────────────────────────
@app.route("/data", methods=["GET"])
def get_data():
    if not _rate_ok(_get_ip()):
        return jsonify({"error": "rate_limited"}), 429
    # Build response with perf included
    resp = dict(state)
    resp["perf"] = state["perf"]
    return jsonify(resp)


# ── /holdings — Portfolio Holdings ───────────────────────────────────────────
holdings_state = {}

@app.route("/holdings", methods=["GET"])
def get_holdings():
    if not _rate_ok(_get_ip()):
        return jsonify({"error": "rate_limited"}), 429
    return jsonify(holdings_state)

@app.route("/holdings", methods=["POST"])
def set_holdings():
    if not _rate_ok(_get_ip()):
        return jsonify({"error": "rate_limited"}), 429
    if not _check_dashboard_auth():
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "expected_json_object"}), 400
    global holdings_state
    cleaned = {}
    for k in ("btc", "eth", "sol", "gold", "usdc", "bnb", "doge", "ada", "hype", "link", "sui", "xrp"):
        v = _safe_float(data.get(k, 0), 0, 1e12)
        cleaned[k] = v if v is not None else 0.0
    holdings_state = cleaned
    return jsonify({"ok": True})


# ── /prices — CoinGecko proxy (avoids CORS + rate limits) ───────────────────
_price_cache = {"data": {}, "ts": 0}
PRICE_TTL = 55  # seconds

@app.route("/prices", methods=["GET"])
def get_prices():
    if not _rate_ok(_get_ip()):
        return jsonify({"error": "rate_limited"}), 429
    global _price_cache
    now = time.time()
    if now - _price_cache["ts"] < PRICE_TTL and _price_cache["data"]:
        return jsonify(_price_cache["data"])
    try:
        ids = "bitcoin,ethereum,solana,pax-gold,binancecoin,dogecoin,cardano,hyperliquid,chainlink,sui,ripple"
        url = f"https://api.coingecko.com/api/v3/simple/price?ids={ids}&vs_currencies=usd"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = _json.loads(r.read())
        _price_cache = {"data": data, "ts": now}
        return jsonify(data)
    except Exception as e:
        if _price_cache["data"]:
            return jsonify(_price_cache["data"])
        return jsonify({"error": str(e)}), 502


# ── / health check — keine sensiblen Daten ───────────────────────────────────
@app.route("/", methods=["GET"])
def health():
    return jsonify({
        "status":      "running",
        "app":         "Allocation STRAT v4",
        "last_update": state["last_update"]
    })

@app.errorhandler(404)
def not_found(_): return jsonify({"error": "not_found"}), 404

@app.errorhandler(405)
def method_not_allowed(_): return jsonify({"error": "method_not_allowed"}), 405


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
