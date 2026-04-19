from flask import Flask, render_template, request, session, redirect, url_for
import random, time

app = Flask(__name__)
app.secret_key = "FAIZA_MASTER_SECURITY_KEY"

# --- 1. Database ---
USER = {
    "username": "faiza", 
    "password": "0312", 
    "email": "faizach0312@gmail.com"
}

# --- 2. System State & Monitoring ---
state = {}        # Failed attempts aur locks history
otp_store = {}    # Active OTPs aur expiry
used_otps = set() # Replay Attack detection list
logs = []         # System logs

# --- 3. Helper Functions ---
def init_user(u):
    if u not in state:
        state[u] = {"pwd_fails": 0, "otp_fails": 0, "otp_success_count": 0, "lock": 0}

def log_event(u, event, severity="Medium"):
    logs.append({"user": u, "event": event, "time": time.strftime("%H:%M:%S"), "severity": severity})

# --- 4. Main Routes ---

@app.route('/')
def home():
    msg = request.args.get('msg')
    return render_template("login.html", attempts_left=3, msg=msg)

@app.route('/login', methods=['POST'])
def login():
    u_name = request.form.get("username")
    pwd = request.form.get("password")
    
    init_user(u_name)
    u = state[u_name]

    # Rule: Check if Account is Locked
    if u["lock"] > time.time():
        rem = int(u["lock"] - time.time())
        return render_template("login.html", error="account_locked", lock_seconds=rem)

    # Success Login
    if u_name == USER["username"] and pwd == USER["password"]:
        # Agar user ne 3 dfa sahi OTP dali pr baar baar password glt daal rha tha (Brute Force)
        if u["otp_success_count"] >= 3:
            u["lock"] = time.time() + 30
            log_event(u_name, "BRUTE FORCE DETECTED (OTP Abuse)", "Critical")
            return render_template("login.html", error="brute_force", lock_seconds=30)
        
        session["user"] = u_name
        log_event(u_name, "Successful Login", "Safe")
        return redirect('/dashboard')

    # Wrong Password Case
    u["pwd_fails"] += 1
    log_event(u_name, f"Wrong Password Attempt {u['pwd_fails']}", "High")

    # Rule: 3 Wrong Passwords -> Trigger OTP
    if u["pwd_fails"] >= 3:
        otp = str(random.randint(1000, 9999))
        otp_store[u_name] = {"code": otp, "expiry": time.time() + 40}
        session["temp_user"] = u_name
        print(f"--- [MFA OTP]: {otp} (40s expiry) ---")
        return render_template("otp.html")

    return render_template("login.html", error="invalid", attempts_left=(3 - u["pwd_fails"]))

@app.route('/verify', methods=['POST'])
def verify():
    otp_input = request.form.get("otp")
    u_name = session.get("temp_user")
    init_user(u_name)
    u = state[u_name]
    active_otp = otp_store.get(u_name)

    # Rule: Replay Attack Detection (Used OTP)
    if otp_input in used_otps:
        log_event(u_name, "REPLAY ATTACK BLOCKED", "Critical")
        return render_template("otp.html", error="replay_attack")

    # Correct OTP Verification
    if active_otp and active_otp["code"] == otp_input:
        if time.time() > active_otp["expiry"]:
            return render_template("otp.html", error="expired")
        
        used_otps.add(otp_input) # Mark as used to prevent replay
        u["otp_success_count"] += 1
        u["otp_fails"] = 0
        return redirect(url_for('home', msg="OTP Verified! Identity Confirmed. Now Login."))

    # Rule: 3 Wrong OTPs -> Account Lock
    u["otp_fails"] += 1
    if u["otp_fails"] >= 3:
        u["lock"] = time.time() + 30
        log_event(u_name, "Account Locked (MFA Failed)", "High")
        return render_template("login.html", error="account_locked", lock_seconds=30)
    
    return render_template("otp.html", error="wrong_otp", otp_attempts=(3-u["otp_fails"]))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form.get("email")
        if email == USER["email"]:
            token = str(random.randint(100000, 999999))
            otp_store["recovery_token"] = token
            link = f"http://127.0.0.1:5000/reset-password?token={token}"
            # Gmail Link Simulation
            return f"""
            <div style="background:#f1f5f9; padding:20px; font-family:Arial; border:1px solid #ccc; width:450px; margin:50px auto; text-align:center;">
                <h3>📧 Gmail Simulation</h3>
                <p>To: <b>{email}</b></p><hr>
                <p>Someone requested a password reset. Click below to continue:</p>
                <a href='{link}' style="background:#06b6d4; color:white; padding:10px 20px; text-decoration:none; border-radius:5px; font-weight:bold;">Reset My Password</a>
            </div>
            """
        return "Email address not found!"
    return render_template("recovery.html", step='forgot')

@app.route('/reset-password')
def reset():
    token = request.args.get("token")
    if token == otp_store.get("recovery_token"):
        return render_template("recovery.html", step='reset', token=token)
    return "Invalid or Expired Link"

@app.route('/update-password', methods=['POST'])
def update():
    new_p = request.form.get("password")
    token = request.form.get("token")
    if token == otp_store.get("recovery_token"):
        USER["password"] = new_p
        otp_store.pop("recovery_token")
        log_event(USER["username"], "Password Updated via Recovery", "Safe")
        return redirect(url_for('home', msg="Password updated! Please login with your new password."))
    return "Verification Failed"

@app.route('/dashboard')
def dashboard():
    if "user" not in session: return redirect("/")
    u_name = session["user"]
    u = state.get(u_name, {"pwd_fails": 0})
    
    fails = u["pwd_fails"]
    risk = min(fails * 33, 100) # Each fail adds 33%
    status = "Secure" if risk < 35 else "Warning" if risk < 70 else "CRITICAL"
    
    return render_template("dashboard.html", user=u_name, attempts=fails, risk=risk, status=status)

@app.route('/logs')
def show_logs():
    return render_template("logs.html", logs=logs)

if __name__ == "__main__":
    app.run(debug=True)