import os
import re
import sqlite3
import requests
import pickle
from datetime import datetime

import fitz       
import docx2txt
import pytesseract
from PIL import Image

from flask import Flask, render_template, request, redirect, url_for, session
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from sklearn.feature_extraction.text import TfidfVectorizer

app = Flask(__name__)
app.secret_key = 'your_super_secret_key_123'

# ---- Mail config ----
app.config.update(
    MAIL_SERVER='sandbox.smtp.mailtrap.io',
    MAIL_PORT=2525,
    MAIL_USERNAME='648a0b0130dd29',
    MAIL_PASSWORD='9c891942fc8586',
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_DEFAULT_SENDER='noreply@threatdetector.com'
)
mail = Mail(app)

# ---- Upload settings ----
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png', 'docx'}

# ---- Telegram ----
TELEGRAM_TOKEN = ""
GUARDIAN_CHAT_IDS = ["", ""]

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text(path, ext):
    if ext == 'pdf':
        txt = ''
        for p in fitz.open(path):
            txt += p.get_text()
        return txt
    if ext in ['jpg', 'jpeg', 'png']:
        return pytesseract.image_to_string(Image.open(path))
    if ext == 'docx':
        return docx2txt.process(path)
    return ''

def send_telegram_alert(msg, ids):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    for cid in ids:
        try:
            requests.post(url, data={"chat_id": cid, "text": msg})
        except:
            pass

# ---- Load resources ----
with open("stopwords.txt") as f:
    stopwords = f.read().splitlines()

vocab = pickle.load(open("tfidfvectoizer.pkl", "rb"))
model = pickle.load(open("LinearSVCTuned.pkl", "rb"))

def clean_text(t):
    t = t.lower()
    t = re.sub(r'(.)\1{2,}', r'\1', t)
    t = re.sub(r'[^a-z0-9\s]', '', t)
    for k, v in {"0":"o","1":"i","@":"a","$":"s","3":"e"}.items():
        t = t.replace(k, v)
    return " ".join(w for w in t.split() if w not in stopwords)

# ---- Ensure users table ----
def init_db():
    conn = sqlite3.connect('users.db'); c = conn.cursor()
    c.execute('''
      CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        guardian_id TEXT
      )
    ''')
    conn.commit(); conn.close()
init_db()

# ---- Routes ----

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/register', methods=['GET','POST'])
@app.route('/register_user', methods=['GET','POST'])
def register_user():
    if request.method == 'POST':
        u = request.form['username'].strip()
        p = request.form['password'].strip()
        g = request.form.get('guardian_id','').strip()
        conn = sqlite3.connect('users.db'); c = conn.cursor()
        try:
            c.execute("INSERT INTO users(username,password,guardian_id) VALUES(?,?,?)", (u,p,g))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "<h3>Username exists</h3><a href='/register'>Back</a>"
        conn.close()
        return redirect(url_for('login'))
    return render_template('register_user.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = request.form['username'].strip()
        p = request.form['password'].strip()
        conn = sqlite3.connect('users.db'); c = conn.cursor()
        c.execute("SELECT guardian_id FROM users WHERE username=? AND password=?", (u,p))
        row = c.fetchone(); conn.close()
        if row:
            session['username'] = u
            session['guardian_id'] = row[0]
            return redirect(url_for('index'))
        return "<h3>Invalid login</h3><a href='/login'>Back</a>"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/index', methods=['GET', 'POST'])
def index():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Preload from upload if set, else blank
    user_input = session.pop('preload_text', '')
    prediction = None

    if request.method == 'POST':
        raw_input = request.form.get('text', '').strip()
        if raw_input:
            user_input = clean_text(raw_input)

            vectorizer = TfidfVectorizer(stop_words=stopwords, lowercase=True, vocabulary=vocab)
            X = vectorizer.fit_transform([user_input])
            prediction = model.predict(X)[0]

            if prediction == 1:
                msg = f"⚠️ Alert: A threatening message was detected!\n User: {session['username']}\n Message: \"{raw_input}\""
                rec = [session.get('guardian_id')] if session.get('guardian_id') else []
                send_telegram_alert(msg, rec + GUARDIAN_CHAT_IDS)
                with open('alerts_log.txt', 'a') as log:
                    log.write(f"{datetime.now()} | {session['username']} | {raw_input}\n")
            
            # ✅ Clear the text box after analysis
            user_input = ''

    return render_template('index.html',
                           prediction=prediction,
                           user_input=user_input,
                           username=session.get('username'))
                           

@app.route('/upload', methods=['GET','POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or f.filename=='' or not allowed_file(f.filename):
            return "<h3>Invalid file</h3><a href='/upload'>Back</a>"
        fn = secure_filename(f.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], fn)
        f.save(path)
        ext = fn.rsplit('.',1)[1].lower()
        txt = extract_text(path, ext)
        session['preload_text'] = txt
        return redirect(url_for('index'))
    return render_template('upload.html')

@app.route('/alerts')
def alerts():
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']
    user_alerts = []

    if os.path.exists('alerts_log.txt'):
        with open('alerts_log.txt', 'r') as file:
            for line in file:
                if '|' not in line:
                    continue  # skip malformed lines

                parts = line.strip().split('|')
                if len(parts) == 3:
                    timestamp, username, message = [p.strip() for p in parts]
                    if username == current_user:
                        user_alerts.append({
                            'time': timestamp,
                            'user': username,
                            'message': message
                        })

    return render_template('alerts.html', alerts=user_alerts)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/suggestion', methods=['POST'])
def suggestion():
    msg = request.form.get('message','')
    user = session.get('username','Anonymous')
    mail.send(Message(f"Suggestion from {user}", recipients=['admin@threatdetector.com'], body=msg))
    return redirect(url_for('about'))

if __name__=='__main__':
    app.run(debug=True)
