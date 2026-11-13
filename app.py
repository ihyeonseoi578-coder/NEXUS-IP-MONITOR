
from flask import Flask, request, redirect, session, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import sqlite3

app = Flask(__name__)
app.secret_key = "nexus-change-this-secret"

DB = "nexus.db"

def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip TEXT,
            time TEXT
        )
    """)
    conn.commit()
    conn.close()

HTML = """
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>NEXUS IP MONITOR</title>
<style>
body{background:#080d18;color:white;font-family:Arial;margin:0;padding:40px}
main{max-width:700px;margin:auto}
.card{background:#141e30;padding:25px;margin:20px 0;border-radius:14px}
input{display:block;width:95%;padding:13px;margin:12px 0;background:#080d18;color:white;border:1px solid #33445f;border-radius:7px}
button{background:#1685ff;color:white;padding:12px 22px;border:0;border-radius:7px;cursor:pointer}
h1{color:#55aaff}
a{color:#55aaff}
table{width:100%;text-align:left}
td,th{padding:10px;border-bottom:1px solid #33445f}
</style>
</head>
<body>
<main>
<h1>NEXUS IP MONITOR</h1>
<p>접속 기록 수집 및 관리자 모니터링 시스템</p>

{% if not session.get('user') %}
<div class="card">
<h2>로그인</h2>
<form action="/login" method="post">
<input name="username" placeholder="아이디" required>
<input name="password" type="password" placeholder="비밀번호" required>
<button>로그인</button>
</form>
</div>
<div class="card">
<h2>회원가입</h2>
<form action="/register" method="post">
<input name="username" placeholder="아이디" required>
<input name="password" type="password" placeholder="비밀번호" required>
<label><input type="checkbox" name="consent" required> 로그인 시 접속 IP와 시간이 기록되는 것에 동의합니다.</label>
<br><br>
<button>회원가입</button>
</form>
</div>
{% else %}
<div class="card">
<h2>로그인 성공</h2>
<p>계정: {{session['user']}}</p>
<p>현재 접속 IP: {{ip}}</p>
<a href="/logout">로그아웃</a>
</div>
{% if session['user'] == 'admin' %}
<div class="card">
<h2>관리자 접속 기록</h2>
<table>
<tr><th>계정</th><th>IP 주소</th><th>접속 시간</th></tr>
{% for log in logs %}
<tr><td>{{log[0]}}</td><td>{{log[1]}}</td><td>{{log[2]}}</td></tr>
{% endfor %}
</table>
</div>
{% endif %}
{% endif %}
</main>
</body>
</html>
"""

@app.route("/")
def home():
    if "user" not in session:
        return render_template_string(HTML)

    username = session["user"]
    ip = request.remote_addr

    conn = sqlite3.connect(DB)
    conn.execute(
        "INSERT INTO logs (username, ip, time) VALUES (?, ?, ?)",
        (username, ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()

    logs = conn.execute(
        "SELECT username, ip, time FROM logs ORDER BY id DESC LIMIT 100"
    ).fetchall() if username == "admin" else []

    conn.close()
    return render_template_string(HTML, ip=ip, logs=logs)

@app.route("/register", methods=["POST"])
def register():
    if not request.form.get("consent"):
        return "IP 기록 동의가 필요합니다."

    username = request.form["username"].strip()
    password = request.form["password"]

    if not username or len(password) < 8:
        return "아이디를 입력하고 비밀번호는 8자 이상 사용하세요."

    try:
        conn = sqlite3.connect(DB)
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, generate_password_hash(password))
        )
        conn.commit()
        conn.close()
        return redirect("/")
    except sqlite3.IntegrityError:
        return "이미 존재하는 아이디입니다."

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"].strip()
    password = request.form["password"]

    conn = sqlite3.connect(DB, timeout=30)
    user = conn.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()

    if user and check_password_hash(user[0], password):
        session["user"] = username
        return redirect("/")

    return "로그인 실패: 아이디 또는 비밀번호를 확인하세요."

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)