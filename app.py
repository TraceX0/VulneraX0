from flask import Flask, render_template, request, redirect, session, g, send_from_directory, make_response
import sqlite3
import os
import threading
import time
import xml.etree.ElementTree as ET
from functools import wraps
import random
import smtplib
from email.mime.text import MIMEText
import uuid


app = Flask(__name__)
app.secret_key = 'VulneraX0_s3cr3t@325662'

DATABASE = 'database.db'
OTP_STORE = {}
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# ---------------- DB Connection ---------------- #
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db:
        db.close()

# ---------------- Auth ---------------- #
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# ---------------- Routes ---------------- #

@app.route('/')
def index():
    return redirect('/login')

# ---------- Login (Weak Auth) ---------- #
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
        if user:
            session['user'] = username
            import uuid
            # Generate a random user_session token and store it in DB for this user
            user_session_token = str(uuid.uuid4())
            db.execute('UPDATE users SET session_token = ? WHERE id = ?', (user_session_token, user['id']))
            db.commit()
            resp = redirect('/dashboard')
            resp.set_cookie('user_session', user_session_token, httponly=True)
            return resp
        else:
            return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

# ---------- Dashboard ---------- #
@app.route('/dashboard')
@login_required
def dashboard():
    # Use cached balance for UI misdirection, but don't mention it in the UI
    balance = session.get('cached_balance', 10000)
    return render_template('dashboard.html', user=session['user'], balance=balance)

# ---------- IDOR ---------- #
@app.route('/profile')
@login_required
def profile():
    db = get_db()
    # Get the logged-in user's info
    user = db.execute('SELECT * FROM users WHERE username = ?', (session['user'],)).fetchone()
    if not user:
        return redirect('/login')
    documents = db.execute('SELECT * FROM documents WHERE user_id = ?', (user['id'],)).fetchall() if db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='documents'").fetchone() else []
    transactions = db.execute('SELECT * FROM transactions WHERE user_id = ?', (user['id'],)).fetchall() if db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='transactions'").fetchone() else []
    balance_row = db.execute('SELECT balance FROM balance WHERE username = ?', (session['user'],)).fetchone()
    balance = balance_row['balance'] if balance_row else 0

    # Reflected XSS lab logic
    query = request.args.get('q', '')
    warning = None
    # Block only basic payloads
    forbidden = ['<script', 'onerror', 'alert(', 'onload']
    if any(f in query.lower() for f in forbidden):
        warning = 'Your search contains forbidden keywords.'
        query = ''

    return render_template('profile.html', user=user, documents=documents, transactions=transactions, balance=balance, query=query, warning=warning)

# ---------- SQLi ---------- #
@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    db = get_db()
    results = db.execute(f"SELECT * FROM transactions WHERE details LIKE '%{query}%' ").fetchall()
    return render_template('search.html', results=results, query=query)

# ---------- XSS ---------- #
@app.route('/comment', methods=['GET', 'POST'])
@login_required
def comment():
    db = get_db()
    if request.method == 'POST':
        comment = request.form['comment']
        db.execute("INSERT INTO comments (content) VALUES (?)", (comment,))
        db.commit()
    comments = db.execute("SELECT * FROM comments").fetchall()
    return render_template('comment.html', comments=comments)

# ---------- XXE ---------- #
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    output = ""
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (session['user'],)).fetchone()
    if request.method == 'POST':
        file = request.files['xmlfile']
        if file:
            filename = file.filename
            # Weak extension check (bypassable)
            if not filename.lower().endswith('.xml'):
                output = "Only .xml files are allowed!"
            else:
                # Save file to uploads folder (no MIME/content check)
                save_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(save_path)
                # Simulate RCE by echoing a fake command if .php in filename
                if '.php' in filename.lower():
                    output = f"Fake RCE: Executed command in {filename}"
                else:
                    output = f"File uploaded: <a href='/uploads/{filename}' target='_blank'>{filename}</a>"
                # Save document info to DB
                db.execute('INSERT INTO documents (user_id, filename, uploaded_at) VALUES (?, ?, DATE(\"now\"))', (user['id'], filename))
                db.commit()
    return render_template('upload.html', output=output)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    # Simulate web shell for .php files
    if filename.lower().endswith('.php') or '.php.' in filename.lower():
        cmd = request.args.get('cmd', '')
        if cmd == 'ls':
            return '<pre>flag.txt\nshell.php.xml\nindex.php</pre>'
        elif cmd == 'cat flag.txt' or cmd == 'cat+flag.txt':
            return '<pre>VULNERAX0{n1c3_sh3ll_byp4ss_bruh}</pre>'
        else:
            return '<pre>Unknown or empty command</pre>'
    return send_from_directory(UPLOAD_FOLDER, filename)

# ---------- Race Condition ---------- #
@app.route('/balance-transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    db = get_db()
    sender_user = db.execute('SELECT * FROM users WHERE username = ?', (session['user'],)).fetchone()
    sender_balance_row = db.execute('SELECT balance FROM balance WHERE username = ?', (session['user'],)).fetchone()
    sender_balance = sender_balance_row['balance'] if sender_balance_row else 0
    is_admin = False
    user_row = db.execute('SELECT * FROM users WHERE username = ?', (session['user'],)).fetchone()
    if user_row and 'role' in user_row.keys() and user_row['role'] == 'admin':
        is_admin = True
    # Daily limit logic (skip for admin)
    import datetime
    today = datetime.date.today().isoformat()
    if not is_admin:
        limit_row = db.execute('SELECT amount_sent_today, last_reset FROM daily_limits WHERE user_id = ?', (sender_user['id'],)).fetchone()
        if not limit_row or limit_row['last_reset'] != today:
            db.execute('REPLACE INTO daily_limits (user_id, amount_sent_today, last_reset) VALUES (?, 0, ?)', (sender_user['id'], today))
            db.commit()
            amount_sent_today = 0
        else:
            amount_sent_today = limit_row['amount_sent_today']
        daily_limit = 5000
        remaining_limit = max(0, daily_limit - amount_sent_today)
    else:
        amount_sent_today = 0
        daily_limit = None
        remaining_limit = None
    msg = ""
    if request.method == 'POST':
        to_user = request.form['to_user']
        try:
            amount = int(request.form['amount'])
        except (ValueError, TypeError):
            msg = "Invalid amount."
            return render_template('transfer.html', msg=msg, balance=sender_balance)
        if to_user == session['user']:
            msg = "You cannot transfer money to yourself."
            return render_template('transfer.html', msg=msg, balance=sender_balance)
        receiver_user = db.execute('SELECT * FROM users WHERE username = ?', (to_user,)).fetchone()
        if not receiver_user:
            msg = "Recipient does not exist."
            return render_template('transfer.html', msg=msg, balance=sender_balance)
        receiver_balance_row = db.execute('SELECT balance FROM balance WHERE username = ?', (to_user,)).fetchone()
        receiver_balance = receiver_balance_row['balance'] if receiver_balance_row else 0
        if sender_balance < amount:
            msg = "Insufficient balance."
            return render_template('transfer.html', msg=msg, balance=sender_balance)
        if not is_admin and amount > remaining_limit:
            if amount_sent_today == 0:
                msg = "You can only send up to ₹5000 per day. Please enter an amount less than or equal to ₹5000."
            else:
                msg = f"You can only send ₹{remaining_limit} more today."
            return render_template('transfer.html', msg=msg, balance=sender_balance)
        import time, uuid
        time.sleep(2)
        # Update balances
        db.execute('UPDATE balance SET balance = balance - ? WHERE username = ?', (amount, session['user']))
        db.execute('UPDATE balance SET balance = balance + ? WHERE username = ?', (amount, to_user))
        # Log transactions for both sender and receiver
        txn_id = str(uuid.uuid4())[:8]
        sender_msg = f"Sent ₹{amount} to {to_user} (Txn ID: {txn_id})"
        receiver_msg = f"Received ₹{amount} from {session['user']} (Txn ID: {txn_id})"
        db.execute('INSERT INTO transactions (user_id, details) VALUES (?, ?)', (sender_user['id'], sender_msg))
        db.execute('INSERT INTO transactions (user_id, details) VALUES (?, ?)', (receiver_user['id'], receiver_msg))
        # Update daily limit only for non-admin
        if not is_admin:
            db.execute('UPDATE daily_limits SET amount_sent_today = amount_sent_today + ? WHERE user_id = ?', (amount, sender_user['id']))
        db.commit()
        # Refresh balances
        sender_balance_row = db.execute('SELECT balance FROM balance WHERE username = ?', (session['user'],)).fetchone()
        sender_balance = sender_balance_row['balance'] if sender_balance_row else 0
        msg = f"Transferred ₹{amount} to {to_user} (Txn ID: {txn_id})"
    return render_template('transfer.html', msg=msg, balance=sender_balance)

# ---------- Logout ---------- #
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ---------- Register ---------- #
@app.route('/register', methods=['GET', 'POST'])
def register():
    db = get_db()
    error = None
    otp_sent = False
    if request.method == 'POST':
        if 'otp' in request.form:
            # OTP verification step
            email = session.get('pending_email')
            otp_input = request.form['otp']
            if email and OTP_STORE.get(email) == otp_input:
                username = session.get('pending_username')
                password = session.get('pending_password')
                db.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, password))
                db.execute("INSERT INTO balance (username, balance) VALUES (?, ?) ", (username, 10000))
                db.commit()
                OTP_STORE.pop(email, None)
                session.pop('pending_email', None)
                session.pop('pending_username', None)
                session.pop('pending_password', None)
                return redirect('/login')
            else:
                error = 'Invalid OTP. Please try again.'
                otp_sent = True
        else:
            # Registration step
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            # Check if user/email exists
            if db.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email)).fetchone():
                error = 'Username or email already exists.'
            else:
                otp = f"{random.randint(1000, 9999)}"
                OTP_STORE[email] = otp
                session['pending_email'] = email
                session['pending_username'] = username
                session['pending_password'] = password
                # Send OTP via email
                send_otp_email(email, otp)
                otp_sent = True
    return render_template('register.html', error=error, otp_sent=otp_sent)

def send_otp_email(to_email, otp):
    # Updated SMTP config for Docker-to-host MailHog
    smtp_host = 'host.docker.internal'
    smtp_port = 1025
    from_email = 'noreply@vulneraX0.com'
    subject = 'Your VulneraX0 OTP Code'
    body = f'Your OTP code is: {otp}'
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email
    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.sendmail(from_email, [to_email], msg.as_string())
    except Exception as e:
        print(f"Failed to send OTP email: {e}")

# ---------- Init DB (only run once) ---------- #
def init_db():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    # Users table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            password TEXT,
            session_token TEXT,
            role TEXT
        )
    ''')
    # Transactions table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            details TEXT
        )
    ''')
    # Documents table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            filename TEXT,
            uploaded_at TEXT
        )
    ''')
    # Comments table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY,
            name TEXT,
            content TEXT,
            timestamp TEXT
        )
    ''')
    # Balance table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS balance (
            username TEXT,
            balance INTEGER
        )
    ''')
    # Daily limits table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS daily_limits (
            user_id INTEGER PRIMARY KEY,
            amount_sent_today INTEGER DEFAULT 0,
            last_reset TEXT
        )
    ''')
    conn.commit()

    # Insert default users if table is empty
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO users (id, username, email, password, session_token, role) VALUES (1, 'admin', 'admin@vulneraX0.com', 'admin', NULL, 'admin')")
        cur.execute("INSERT INTO users (id, username, email, password, session_token, role) VALUES (2, 'john', 'john@example.com', 'john', NULL, 'user')")

    # Insert default balances if table is empty
    cur.execute("SELECT COUNT(*) FROM balance")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO balance (username, balance) VALUES ('admin', 10000)")
        cur.execute("INSERT INTO balance (username, balance) VALUES ('john', 10000)")

    # Insert default comments if table is empty
    cur.execute("SELECT COUNT(*) FROM comments")
    if cur.fetchone()[0] == 0:
        import datetime
        now = datetime.datetime.now()
        cur.execute("INSERT INTO comments (name, content, timestamp) VALUES (?, ?, ?)", ("Mahi", "Great fintech platform! Easy to use and secure.", (now - datetime.timedelta(days=2)).strftime('%Y-%m-%d %H:%M:%S')))
        cur.execute("INSERT INTO comments (name, content, timestamp) VALUES (?, ?, ?)", ("Rohit", "I love the fast transfers and simple dashboard.", (now - datetime.timedelta(days=1, hours=3)).strftime('%Y-%m-%d %H:%M:%S')))
        cur.execute("INSERT INTO comments (name, content, timestamp) VALUES (?, ?, ?)", ("Virat", "Customer support was very helpful. Thanks!", (now - datetime.timedelta(hours=5)).strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()

@app.route('/update-role', methods=['POST'])
@login_required
def update_role():
    db = get_db()
    # Only allow if current user is admin
    user = db.execute('SELECT * FROM users WHERE username = ?', (session['user'],)).fetchone()
    if not user or user['role'] != 'admin':
        return 'Forbidden', 403
    # Simulate processing delay
    import time
    time.sleep(2.5)
    # Downgrade role in DB
    db.execute('UPDATE users SET role = ? WHERE username = ?', ('user', session['user']))
    db.commit()
    # Update session role
    session['role'] = 'user'
    return 'Role updated successfully.'

@app.route('/transfer', methods=['POST'])
@login_required
def admin_transfer():
    if session.get('role') != 'admin':
        return 'Forbidden', 403
    db = get_db()
    sender = session['user']
    receiver = 'john'  # Hardcoded recipient
    amount = 5000
    # Check sender balance
    sender_balance = db.execute('SELECT balance FROM balance WHERE username=?', (sender,)).fetchone()
    if not sender_balance or sender_balance['balance'] < amount:
        return 'Insufficient funds', 400
    # Update balances
    db.execute('UPDATE balance SET balance = balance - ? WHERE username=?', (amount, sender))
    db.execute('UPDATE balance SET balance = balance + ? WHERE username=?', (amount, receiver))
    # Log transaction
    import uuid
    txn_id = str(uuid.uuid4())[:8]
    txn_msg = f"₹{amount} sent to {receiver} (Txn ID: {txn_id})"
    user = db.execute('SELECT * FROM users WHERE username = ?', (sender,)).fetchone()
    db.execute('INSERT INTO transactions (user_id, details) VALUES (?, ?)', (user['id'], txn_msg))
    db.commit()
    return f'Transfer successful. ₹{amount} sent to {receiver} (Txn ID: {txn_id})'

# ---------- Race Condition Vulnerability ---------- #
@app.route('/race-transfer', methods=['GET', 'POST'])
@login_required
def race_transfer():
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (session['user'],)).fetchone()
    user_id = user['id']
    is_admin = False
    if user and 'role' in user.keys() and user['role'] == 'admin':
        is_admin = True
    # Get balance
    bal_row = db.execute('SELECT balance FROM balance WHERE user_id = ?', (user_id,)).fetchone()
    balance = bal_row['balance'] if bal_row else 0
    # Get daily limit (skip for admin)
    import datetime
    today = datetime.date.today().isoformat()
    if not is_admin:
        limit_row = db.execute('SELECT amount_sent_today, last_reset FROM daily_limits WHERE user_id = ?', (user_id,)).fetchone()
        if not limit_row or limit_row['last_reset'] != today:
            # Reset daily limit if new day
            db.execute('REPLACE INTO daily_limits (user_id, amount_sent_today, last_reset) VALUES (?, 0, ?)', (user_id, today))
            db.commit()
            amount_sent_today = 0
        else:
            amount_sent_today = limit_row['amount_sent_today']
        daily_limit = 5000
        remaining_limit = max(0, daily_limit - amount_sent_today)
    else:
        amount_sent_today = 0
        daily_limit = None
        remaining_limit = None
    msg = ""
    if request.method == 'POST':
        to_user = request.form['to_user']
        try:
            amount = int(request.form['amount'])
        except (ValueError, TypeError):
            msg = "Invalid amount."
            return render_template('race_transfer.html', balance=balance, remaining_limit=remaining_limit, msg=msg)
        # SECURE: Fetch latest daily limit and balance before processing
        if not is_admin:
            limit_row = db.execute('SELECT amount_sent_today, last_reset FROM daily_limits WHERE user_id = ?', (user_id,)).fetchone()
            if not limit_row or limit_row['last_reset'] != today:
                db.execute('REPLACE INTO daily_limits (user_id, amount_sent_today, last_reset) VALUES (?, 0, ?)', (user_id, today))
                db.commit()
                amount_sent_today = 0
            else:
                amount_sent_today = limit_row['amount_sent_today']
            remaining_limit = max(0, daily_limit - amount_sent_today)
        bal_row = db.execute('SELECT balance FROM balance WHERE user_id = ?', (user_id,)).fetchone()
        balance = bal_row['balance'] if bal_row else 0
        if not is_admin and amount > remaining_limit:
            msg = f"Daily limit exceeded. You can send up to ₹{remaining_limit} today."
            return render_template('race_transfer.html', balance=balance, remaining_limit=remaining_limit, msg=msg)
        if amount > balance:
            msg = "Insufficient balance."
            return render_template('race_transfer.html', balance=balance, remaining_limit=remaining_limit, msg=msg)
        import time
        time.sleep(2.0)
        db.execute('UPDATE balance SET balance = balance - ? WHERE user_id = ?', (amount, user_id))
        recipient = db.execute('SELECT id FROM users WHERE username = ?', (to_user,)).fetchone()
        if not recipient:
            msg = "Recipient does not exist."
            return render_template('race_transfer.html', balance=balance, remaining_limit=remaining_limit, msg=msg)
        db.execute('UPDATE balance SET balance = balance + ? WHERE user_id = ?', (amount, recipient['id']))
        if not is_admin:
            db.execute('UPDATE daily_limits SET amount_sent_today = amount_sent_today + ? WHERE user_id = ?', (amount, user_id))
        import uuid
        txn_id = str(uuid.uuid4())[:8]
        db.execute('INSERT INTO transactions (user_id, to_user, amount, timestamp) VALUES (?, ?, ?, ?)', (user_id, to_user, amount, datetime.datetime.now().isoformat()))
        db.commit()
        msg = f"Transferred ₹{amount} to {to_user} (Txn ID: {txn_id})"
        # Refresh balance and limit
        bal_row = db.execute('SELECT balance FROM balance WHERE user_id = ?', (user_id,)).fetchone()
        balance = bal_row['balance'] if bal_row else 0
        if not is_admin:
            limit_row = db.execute('SELECT amount_sent_today FROM daily_limits WHERE user_id = ?', (user_id,)).fetchone()
            remaining_limit = max(0, daily_limit - (limit_row['amount_sent_today'] if limit_row else 0))
    return render_template('race_transfer.html', balance=balance, remaining_limit=remaining_limit, msg=msg)

@app.route('/api/balance')
@login_required
def api_balance():
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (session['user'],)).fetchone()
    if not user:
        return {'error': 'Not found'}, 404
    bal_row = db.execute('SELECT balance FROM balance WHERE username = ?', (user['username'],)).fetchone()
    balance = bal_row['balance'] if bal_row else 0
    return {'balance': balance}

@app.route('/api/transactions')
@login_required
def api_transactions():
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (session['user'],)).fetchone()
    if not user:
        return {'error': 'Not found'}, 404
    txns = db.execute('SELECT details FROM transactions WHERE user_id = ? ORDER BY rowid DESC LIMIT 10', (user['id'],)).fetchall()
    return {'transactions': [t['details'] for t in txns]}

@app.route('/api/v1/internal-profile/<int:user_id>')
def api_internal_profile_idor(user_id):
    db = get_db()
    user_session = request.cookies.get('user_session')
    if user_session is not None:
        # Only allow access if the user_session matches the session_token in DB for this user
        user = db.execute('SELECT id, username, email, session_token FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user or user['session_token'] != user_session:
            return {'error': 'Forbidden'}, 403
    else:
        # If user_session is missing, allow access to any user_id (IDOR)
        user = db.execute('SELECT id, username, email FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user:
            return {'error': 'User not found'}, 404
    # Fetch balance from balance table using username
    bal_row = db.execute('SELECT balance FROM balance WHERE username = ?', (user['username'],)).fetchone()
    balance = bal_row['balance'] if bal_row else 0
    return {
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'balance': balance
    }

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    db = get_db()
    warning = None
    forbidden = [
        '<script', '</script', 'alert(', '<img src='
    ]
    if request.method == 'POST':
        content = request.form.get('feedback', '')
        if any(f in content.lower() for f in forbidden):
            warning = 'Your comment contains forbidden keywords.'
        else:
            name = session.get('user', 'Anonymous')
            import datetime
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            db.execute('INSERT INTO comments (name, content, timestamp) VALUES (?, ?, ?)', (name, content, timestamp))
            db.commit()
    feedbacks = db.execute('SELECT name, content, timestamp FROM comments ORDER BY id DESC').fetchall()
    resp = make_response(render_template(
        'feedback.html',
        feedbacks=feedbacks,
        warning=warning
    ))
    # Set the flag in a cookie for authenticated users
    if 'user' in session:
        resp.set_cookie('flag', 'VULNERAX0{did_u_ev3n_s4nitiz3_bruh}', httponly=False)
    return resp

if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
