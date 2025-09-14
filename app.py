from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
import random
import time

app = Flask(__name__)
app.secret_key = 'your-strong-secret-key'  # Change for production

# Setup Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# In-memory user database
users = {
    "admin": {"password": "adminpass", "role": "admin"},
    "user": {"password": "userpass", "role": "user"}
}

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, username):
        self.id = username
        self.role = users[username]['role']

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

def admin_required(f):
    @login_required
    def decorated(*args, **kwargs):
        if current_user.role != 'admin':
            flash("Admin access required.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

# Routes

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users and users[username]['password'] == password:
            user = User(username)
            login_user(user)
            flash(f"Welcome, {username}!", "success")
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        flash("Invalid username or password", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    # User dashboard
    return render_template('index.html', role=current_user.role, username=current_user.id)

@app.route('/admin')
@admin_required
def admin():
    # Admin dashboard
    return render_template('admin.html', role=current_user.role, username=current_user.id)

@app.route('/run-audit', methods=['POST'])
@login_required
def run_audit():
    target_url = request.form.get('target_url')
    # Simulate audit process
    time.sleep(1)  
    zap_issues = random.randint(0, 5)
    time.sleep(1)
    nmap_open_ports = random.randint(0, 10)
    compliance_score = random.randint(70, 100)

    recommendations = []
    if zap_issues > 0:
        recommendations.append(f"{zap_issues} OWASP ZAP vulnerabilities found.")
    if nmap_open_ports > 5:
        recommendations.append(f"{nmap_open_ports} open ports detected by Nmap.")
    if compliance_score < 90:
        recommendations.append("Compliance score below target; review standards.")

    report = {
        'target_url': target_url,
        'zap_issues': zap_issues,
        'nmap_open_ports': nmap_open_ports,
        'compliance_score': compliance_score,
        'recommendations': recommendations,
    }
    return render_template('report.html', report=report, role=current_user.role, username=current_user.id)

if __name__ == '__main__':
    app.run(debug=True)
