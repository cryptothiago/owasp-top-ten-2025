import base64
import hashlib
import hmac
import json
import os
import sqlite3
import traceback
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash

from storage import connect, init_db

app = Flask(__name__)
app.secret_key = os.environ.get("LAB_SECRET_KEY", "local-training-key-change-me")

LABS = [
    {
        "id": "a01",
        "code": "A01:2025",
        "title": "Broken Access Control",
        "pt": "Controle de Acesso Quebrado",
        "summary": "IDOR: um usuário autenticado consegue acessar uma nota de outro usuário alterando o ID.",
        "attack": "Entre como alice e troque /vuln/notes/1 por /vuln/notes/2.",
        "fix": "Validar no backend se owner_id corresponde ao usuário autenticado.",
    },
    {
        "id": "a02",
        "code": "A02:2025",
        "title": "Security Misconfiguration",
        "pt": "Configuração Insegura",
        "summary": "Endpoint de diagnóstico expõe informações internas e segredo fictício.",
        "attack": "Acesse /vuln/diagnostics e observe dados que não deveriam estar públicos.",
        "fix": "Remover endpoints de debug, reduzir detalhes e aplicar configuração segura por ambiente.",
    },
    {
        "id": "a03",
        "code": "A03:2025",
        "title": "Software Supply Chain Failures",
        "pt": "Falhas na Cadeia de Suprimentos de Software",
        "summary": "O sistema confia em metadados de pacote fornecidos pelo cliente sem verificar origem ou hash.",
        "attack": "Envie package=flask&version=999.0.0&sha256=qualquer-coisa no verificador vulnerável.",
        "fix": "Usar allowlist, lockfile e hashes verificados antes de aceitar componentes.",
    },
    {
        "id": "a04",
        "code": "A04:2025",
        "title": "Cryptographic Failures",
        "pt": "Falhas Criptográficas",
        "summary": "Senha armazenada em texto claro e 'proteção' de dados usando apenas Base64.",
        "attack": "Abra o perfil vulnerável e veja como Base64 é reversível e não é criptografia.",
        "fix": "Hash de senha com função apropriada e criptografia autenticada para dados sensíveis.",
    },
    {
        "id": "a05",
        "code": "A05:2025",
        "title": "Injection",
        "pt": "Injeção",
        "summary": "Busca SQL constrói a query concatenando entrada do usuário.",
        "attack": "Na busca vulnerável, experimente: ' OR '1'='1' --",
        "fix": "Usar queries parametrizadas e validação adequada de entrada.",
    },
    {
        "id": "a06",
        "code": "A06:2025",
        "title": "Insecure Design",
        "pt": "Design Inseguro",
        "summary": "Cupom de uso único pode ser reutilizado porque a regra de negócio não é aplicada.",
        "attack": "Aplique WELCOME50 repetidas vezes na versão vulnerável.",
        "fix": "Modelar invariantes do negócio e aplicar uso máximo em transação atômica.",
    },
    {
        "id": "a07",
        "code": "A07:2025",
        "title": "Authentication Failures",
        "pt": "Falhas de Autenticação",
        "summary": "Login vulnerável compara senha em texto claro e não possui limitação de tentativas.",
        "attack": "Teste credenciais do laboratório. alice/alice123 é uma conta de demonstração.",
        "fix": "Hash seguro, sessão correta, MFA quando aplicável e limitação de tentativas.",
    },
    {
        "id": "a08",
        "code": "A08:2025",
        "title": "Software or Data Integrity Failures",
        "pt": "Falhas de Integridade de Software ou Dados",
        "summary": "Cookie de perfil é apenas JSON em Base64 e pode ter o campo role adulterado.",
        "attack": "Use o formulário do laboratório para criar um cookie role=admin sem assinatura.",
        "fix": "Assinar/verificar o estado ou manter autorização exclusivamente no servidor.",
    },
    {
        "id": "a09",
        "code": "A09:2025",
        "title": "Security Logging & Alerting Failures",
        "pt": "Falhas de Registro e Alerta de Segurança",
        "summary": "A versão vulnerável realiza ação sensível sem registrar evento de segurança.",
        "attack": "Execute a ação e compare /audit entre os modos vulnerável e corrigido.",
        "fix": "Registrar eventos relevantes com contexto suficiente e alertar padrões suspeitos.",
    },
    {
        "id": "a10",
        "code": "A10:2025",
        "title": "Mishandling of Exceptional Conditions",
        "pt": "Tratamento Incorreto de Condições Excepcionais",
        "summary": "Erro inesperado retorna stack trace e detalhes internos ao usuário.",
        "attack": "Informe zero no divisor da versão vulnerável.",
        "fix": "Falhar de forma segura, registrar detalhes internamente e retornar erro genérico.",
    },
]

APPROVED_PACKAGES = {
    "flask": {"version": "3.1.2", "sha256": "demo-approved-hash-flask-3.1.2"},
    "werkzeug": {"version": "3.1.3", "sha256": "demo-approved-hash-werkzeug-3.1.3"},
}


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = connect()
    user = db.execute(
        "SELECT id, username, role, email FROM users WHERE id = ?", (uid,)
    ).fetchone()
    db.close()
    return user


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Faça login primeiro. Use alice/alice123 para o laboratório.", "warning")
            return redirect(url_for("home"))
        return fn(*args, **kwargs)

    return wrapper


@app.context_processor
def inject_globals():
    return {"labs": LABS, "current_user": current_user()}


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/reset", methods=["POST"])
def reset():
    init_db()
    session.clear()
    flash("Laboratório resetado.", "success")
    return redirect(url_for("home"))


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = connect()
    user = db.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    db.close()

    if user and check_password_hash(user["password_hash"], password):
        session.clear()
        session["user_id"] = user["id"]
        flash(f"Login como {user['username']}.", "success")
    else:
        flash("Credenciais inválidas.", "danger")
    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/lab/<lab_id>")
def lab(lab_id):
    item = next((x for x in LABS if x["id"] == lab_id), None)
    if not item:
        abort(404)
    return render_template("lab.html", lab=item)


# A01 - Broken Access Control
@app.route("/vuln/notes/<int:note_id>")
@login_required
def vuln_note(note_id):
    db = connect()
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    db.close()
    if not note:
        abort(404)
    return render_template("result.html", title="A01 vulnerável — IDOR", data=dict(note))


@app.route("/fixed/notes/<int:note_id>")
@login_required
def fixed_note(note_id):
    user = current_user()
    db = connect()
    note = db.execute(
        "SELECT * FROM notes WHERE id = ? AND owner_id = ?", (note_id, user["id"])
    ).fetchone()
    db.close()
    if not note:
        abort(403)
    return render_template("result.html", title="A01 corrigido — autorização aplicada", data=dict(note))


# A02 - Security Misconfiguration
@app.route("/vuln/diagnostics")
def vuln_diagnostics():
    data = {
        "debug": True,
        "framework": "Flask",
        "database": str(os.path.abspath("lab.db")),
        "fake_internal_secret": "DEMO-ONLY-NOT-A-REAL-SECRET",
        "pythonpath": os.getcwd(),
    }
    return render_template("result.html", title="A02 vulnerável — diagnóstico exposto", data=data)


@app.route("/fixed/diagnostics")
def fixed_diagnostics():
    return render_template(
        "result.html",
        title="A02 corrigido — resposta mínima",
        data={"status": "ok", "service": "owasp-lab"},
    )


# A03 - Software Supply Chain Failures
@app.route("/vuln/package-check")
def vuln_package_check():
    package = request.args.get("package", "flask")
    version = request.args.get("version", "999.0.0")
    sha256 = request.args.get("sha256", "unverified")
    return render_template(
        "result.html",
        title="A03 vulnerável — pacote aceito sem verificação",
        data={"accepted": True, "package": package, "version": version, "sha256": sha256},
    )


@app.route("/fixed/package-check")
def fixed_package_check():
    package = request.args.get("package", "flask")
    version = request.args.get("version", "")
    sha256 = request.args.get("sha256", "")
    approved = APPROVED_PACKAGES.get(package)
    ok = bool(approved and hmac.compare_digest(version, approved["version"]) and hmac.compare_digest(sha256, approved["sha256"]))
    return render_template(
        "result.html",
        title="A03 corrigido — origem/versão/hash validados",
        data={"accepted": ok, "package": package, "expected": approved or "pacote não aprovado"},
    )


# A04 - Cryptographic Failures
@app.route("/vuln/profile/<username>")
def vuln_profile(username):
    db = connect()
    user = db.execute(
        "SELECT username, password_plain, email FROM users WHERE username = ?", (username,)
    ).fetchone()
    db.close()
    if not user:
        abort(404)
    encoded = base64.b64encode(user["email"].encode()).decode()
    return render_template(
        "result.html",
        title="A04 vulnerável — 'segredo' reversível",
        data={
            "username": user["username"],
            "password_stored_as": user["password_plain"],
            "email_base64": encoded,
            "decoded_again": base64.b64decode(encoded).decode(),
        },
    )


@app.route("/fixed/profile/<username>")
def fixed_profile(username):
    db = connect()
    user = db.execute(
        "SELECT username, password_hash, email FROM users WHERE username = ?", (username,)
    ).fetchone()
    db.close()
    if not user:
        abort(404)
    return render_template(
        "result.html",
        title="A04 corrigido — senha não recuperável",
        data={
            "username": user["username"],
            "password_storage": user["password_hash"],
            "sensitive_data_note": "Dados sensíveis reais exigiriam criptografia apropriada e gestão de chaves.",
        },
    )


# A05 - Injection
@app.route("/vuln/search")
def vuln_search():
    q = request.args.get("q", "")
    db = connect()
    sql = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{q}%'"
    try:
        rows = db.execute(sql).fetchall()
        data = {"query_executed": sql, "rows": [dict(r) for r in rows]}
    except sqlite3.Error as exc:
        data = {"query_executed": sql, "error": str(exc)}
    db.close()
    return render_template("result.html", title="A05 vulnerável — SQL concatenado", data=data)


@app.route("/fixed/search")
def fixed_search():
    q = request.args.get("q", "")
    db = connect()
    rows = db.execute(
        "SELECT id, username, email, role FROM users WHERE username LIKE ?", (f"%{q}%",)
    ).fetchall()
    db.close()
    return render_template(
        "result.html",
        title="A05 corrigido — query parametrizada",
        data={"parameter": q, "rows": [dict(r) for r in rows]},
    )


# A06 - Insecure Design
@app.route("/vuln/coupon", methods=["POST"])
def vuln_coupon():
    code = request.form.get("code", "")
    db = connect()
    coupon = db.execute("SELECT * FROM coupons WHERE code = ?", (code,)).fetchone()
    db.close()
    if not coupon:
        data = {"accepted": False, "reason": "cupom inexistente"}
    else:
        data = {
            "accepted": True,
            "discount": coupon["discount"],
            "problem": "max_uses foi ignorado pelo design vulnerável",
        }
    return render_template("result.html", title="A06 vulnerável — regra de negócio ignorada", data=data)


@app.route("/fixed/coupon", methods=["POST"])
def fixed_coupon():
    code = request.form.get("code", "")
    db = connect()
    try:
        db.execute("BEGIN IMMEDIATE")
        coupon = db.execute("SELECT * FROM coupons WHERE code = ?", (code,)).fetchone()
        if not coupon:
            data = {"accepted": False, "reason": "cupom inexistente"}
        elif coupon["uses"] >= coupon["max_uses"]:
            data = {"accepted": False, "reason": "limite de uso atingido"}
        else:
            db.execute("UPDATE coupons SET uses = uses + 1 WHERE code = ?", (code,))
            data = {
                "accepted": True,
                "discount": coupon["discount"],
                "uses_after": coupon["uses"] + 1,
                "max_uses": coupon["max_uses"],
            }
        db.commit()
    finally:
        db.close()
    return render_template("result.html", title="A06 corrigido — invariantes aplicadas", data=data)


# A07 - Authentication Failures
@app.route("/vuln/login", methods=["POST"])
def vuln_login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = connect()
    user = db.execute(
        "SELECT id, username, password_plain FROM users WHERE username = ?", (username,)
    ).fetchone()
    db.close()
    ok = bool(user and user["password_plain"] == password)
    return render_template(
        "result.html",
        title="A07 vulnerável — autenticação fraca",
        data={
            "authenticated": ok,
            "issues": [
                "senha comparada em texto claro",
                "sem rate limit",
                "sem bloqueio progressivo",
            ],
        },
    )


@app.route("/fixed/login", methods=["POST"])
def fixed_login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = connect()
    user = db.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    db.close()
    ok = bool(user and check_password_hash(user["password_hash"], password))
    return render_template(
        "result.html",
        title="A07 corrigido — hash seguro",
        data={
            "authenticated": ok,
            "note": "Em produção, adicione rate limiting, MFA quando aplicável e controles de sessão.",
        },
    )


# A08 - Software/Data Integrity Failures
@app.route("/vuln/profile-cookie")
def vuln_profile_cookie():
    username = request.args.get("username", "alice")
    role = request.args.get("role", "user")
    raw = json.dumps({"username": username, "role": role}).encode()
    cookie = base64.urlsafe_b64encode(raw).decode()
    return render_template(
        "result.html",
        title="A08 vulnerável — estado sem assinatura",
        data={"cookie": cookie, "decoded": json.loads(base64.urlsafe_b64decode(cookie).decode())},
    )


@app.route("/fixed/profile-cookie")
def fixed_profile_cookie():
    username = request.args.get("username", "alice")
    payload = json.dumps({"username": username, "role": "user"}, sort_keys=True)
    signature = hmac.new(
        app.secret_key.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    return render_template(
        "result.html",
        title="A08 corrigido — integridade verificada",
        data={"payload": payload, "hmac_sha256": signature, "note": "Autorização continua devendo ser validada no servidor."},
    )


# A09 - Logging & Alerting Failures
@app.route("/vuln/admin-action", methods=["POST"])
def vuln_admin_action():
    return render_template(
        "result.html",
        title="A09 vulnerável — nenhuma trilha de auditoria",
        data={"action": "demo_sensitive_action", "logged": False},
    )


@app.route("/fixed/admin-action", methods=["POST"])
def fixed_admin_action():
    detail = {
        "action": "demo_sensitive_action",
        "source": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", "")[:80],
    }
    db = connect()
    db.execute(
        "INSERT INTO audit_events(event, detail) VALUES(?, ?)",
        ("security_sensitive_action", json.dumps(detail)),
    )
    db.commit()
    db.close()
    return render_template(
        "result.html",
        title="A09 corrigido — evento registrado",
        data={"action": "demo_sensitive_action", "logged": True},
    )


@app.route("/audit")
def audit():
    db = connect()
    rows = db.execute(
        "SELECT id, event, detail, created_at FROM audit_events ORDER BY id DESC LIMIT 20"
    ).fetchall()
    db.close()
    return render_template("result.html", title="Eventos de auditoria", data={"events": [dict(r) for r in rows]})


# A10 - Exceptional Conditions
@app.route("/vuln/divide")
def vuln_divide():
    value = request.args.get("value", "0")
    try:
        result = 100 / int(value)
        data = {"result": result}
    except Exception:
        data = {"error": traceback.format_exc()}
    return render_template("result.html", title="A10 vulnerável — detalhes internos expostos", data=data)


@app.route("/fixed/divide")
def fixed_divide():
    value = request.args.get("value", "0")
    try:
        parsed = int(value)
        if parsed == 0:
            raise ValueError("zero não é permitido")
        data = {"result": 100 / parsed}
    except (ValueError, TypeError):
        app.logger.warning("Entrada inválida em /fixed/divide")
        data = {"error": "Não foi possível processar a entrada fornecida."}
    return render_template("result.html", title="A10 corrigido — falha segura", data=data)


if __name__ == "__main__":
    init_db()
    host = os.environ.get("LAB_HOST", "127.0.0.1")
    port = int(os.environ.get("LAB_PORT", "5000"))
    app.run(host=host, port=port, debug=False)
