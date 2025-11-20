# app.py
import os
from itsdangerous import URLSafeTimedSerializer 
import json
from backend.code_parser import export_graph_data
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import secrets # For generating secure tokens
import datetime # For token expiry
from flask_moment import Moment
from flask_cors import CORS
from flask_socketio import SocketIO,emit
from backend.sbom_processor import  perform_full_sbom_analysis
from concurrent.futures import ThreadPoolExecutor
from flask_mail import Mail, Message

app = Flask(__name__)
CORS(app)  

ALLOWED_EXTENSIONS = {
    'zip_project': {'zip'},
    'dependency_file': {'txt', 'json', 'yml', 'yaml', 'lock', 'xml', 'mod', 'gradle', 'pom'},
    'docker_tar': {'tar'},
    'existing_sbom_json': {'json', 'xml'}
}

def allowed_file(filename, upload_type):
    if upload_type not in ALLOWED_EXTENSIONS:
        return False
    file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    return file_ext in ALLOWED_EXTENSIONS[upload_type]
upload_folder = "uploads"

if not os.path.exists(upload_folder):
    os.makedirs(upload_folder)
app.config['UPLOAD_FOLDER'] = upload_folder

executor = ThreadPoolExecutor(max_workers=1) 

app.config['SECRET_KEY'] = 'your_super_secret_key_here_replace_me_in_prod'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEBUG'] = True

app.config['MAIL_USERNAME'] = 'letsexploit4@gmail.com'
app.config['MAIL_PASSWORD'] = 'wprw huvt lhhp wuny'
app.config['MAIL_DEFAULT_SENDER'] = 'letsexploit4@gmail.com'
mail = Mail(app)
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

moment = Moment(app)
socket = SocketIO(app, cors_allowed_origins="*",async_mode='eventlet',ping_interval=60,ping_timeout=120)  

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    personal_access_token = db.Column(db.String(256), unique=True, nullable=True)
    token_expiry = db.Column(db.DateTime, nullable=True)
    vscode_connected = db.Column(db.Boolean, default=False, nullable=False)
    vscode_last_connected = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_pat(self):
        self.personal_access_token = secrets.token_urlsafe(64)
        self.token_expiry = datetime.datetime.now() + datetime.timedelta(days=30)
        db.session.add(self)
        db.session.commit()
        return self.personal_access_token

    def is_pat_valid(self):
        return self.personal_access_token and \
               self.token_expiry and \
               self.token_expiry > datetime.datetime.now()

    # ⭐ ADD THESE METHODS INSIDE THE CLASS
    def get_reset_token(self, expires_sec=3600):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return s.dumps({"user_id": self.id})

    @staticmethod
    def verify_reset_token(token, expires_sec=3600):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=expires_sec)
            return User.query.get(data["user_id"])
        except:
            return None

    def __repr__(self):
        return f'<User {self.username}>'

class SBOM(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now)
    project_name = db.Column(db.String(255), nullable=True)
    sbom_type = db.Column(db.String(50), nullable=True)
    raw_sbom_json = db.Column(db.JSON, nullable=False)
    components_for_table = db.Column(db.JSON, nullable=True)
    license_chart_data = db.Column(db.JSON, nullable=True)
    vulnerability_chart_data = db.Column(db.JSON, nullable=True)
    dependency_chart_data = db.Column(db.JSON, nullable=True)

    vulnerability_details = db.relationship(
        'VulnerabilityTable', 
        backref='sbom', 
        uselist=False, # Essential for One-to-One
        cascade="all, delete-orphan",
        foreign_keys='VulnerabilityTable.id'
    )
    def __repr__(self):
        return f'<SBOM {self.id} for User {self.user_id} - {self.project_name}>'


class VulnerabilityTable(db.Model):
    id = db.Column(db.Integer, db.ForeignKey('sbom.id'), primary_key=True)
    userID = db.Column(db.Integer,nullable=False)
    vulnDetails = db.Column(db.JSON, nullable=True)
    graphData = db.Column(db.JSON, nullable=True)
    
    def __repr__(self):
        return f'<VulnerabilityTable ID: {self.id}>'
# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('base.html', title='Home')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        login_id = request.form.get('login_id')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        # Allow login with username OR email
        user = User.query.filter(
            (User.username == login_id) | (User.email == login_id)
        ).first()

        if not user or not user.check_password(password):
            flash('Invalid username/email or password.', 'danger')
            return redirect(url_for('login'))

        login_user(user, remember=remember)
        flash('Logged in successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html', title='Login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Check if username exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'warning')
            return redirect(url_for('register'))

        # Check if email exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists. Please use a different email.', 'warning')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        new_user.generate_pat()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', title='Register')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    # --- IMPORTANT FIX: Refresh current_user to ensure latest PAT data ---
    user_from_db = User.query.get(current_user.id)
    return render_template('dashboard.html', title='Dashboard', user=user_from_db)

# --- API Endpoint for Token Validation ---
@app.route('/api/user_info', methods=['GET'])
def api_user_info():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"message": "Authorization header missing"}), 401

    try:
        token_type, token = auth_header.split(' ', 1)
        if token_type.lower() != 'bearer':
            return jsonify({"message": "Invalid token type, must be Bearer"}), 401
    except ValueError:
        return jsonify({"message": "Invalid Authorization header format"}), 401

    user = User.query.filter_by(personal_access_token=token).first()

    if not user:
        return jsonify({"message": "Invalid or unknown token"}), 401

    if not user.is_pat_valid():
        return jsonify({"message": "Token expired or invalid"}), 401

    return jsonify({
        "message": "Token valid",
        "user": {
            "id": user.id,
            "username": user.username,
            "token_expiry": user.token_expiry.isoformat() if user.token_expiry else None
        }
    }), 200


# --- API Endpoint for PAT Regeneration ---
@app.route('/api/regenerate_pat', methods=['POST'])
@login_required # Only logged-in users can regenerate their PAT
def api_regenerate_pat():
    user = User.query.filter_by(id=current_user.id).first()
    if not user:
        return jsonify({"message": "Unauthorized: Valid token required to set status to 'connected'"}), 401
    
    try:
        new_pat = current_user.generate_pat() 
        user.vscode_connected = False
        user.vscode_last_connected = datetime.datetime.now()
        db.session.commit() 
        app.logger.info("User '%s' VS Code Extension connection status updated to: Disconnected", user.username)
        socket.emit('vscode_status_update', 
                      {'status': 'disconnected', 'last_updated': user.vscode_last_connected.isoformat()}, 
                      room=str(user.id))
        db.session.refresh(current_user)
        return jsonify({
            "message": "Personal Access Token regenerated successfully!",
            "personal_access_token": new_pat,
            "token_expiry": current_user.token_expiry.isoformat()
        }), 200
    except Exception as e:
        db.session.rollback() # Rollback in case of error
        return jsonify({"message": f"Failed to regenerate PAT: {str(e)}"}), 500

# ---- Connection Status Endpoint ----  
@app.route('/api/connection_status', methods=['POST'])
def update_connection_status():
    data = request.get_json()
    if not data:
        return jsonify({"message": "Request body missing or not JSON"}), 400

    status = data.get('status')

    if status not in ['connected', 'disconnected']:
        return jsonify({"message": "Invalid status. Must be 'connected' or 'disconnected'."}), 400

    auth_header = request.headers.get('Authorization')
    token = None
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]

    user = None
    if token:
        user = User.query.filter_by(personal_access_token=token).first()
        if user and not user.is_pat_valid():
            user = None

    if status == 'connected':
        if not user:
            return jsonify({"message": "Unauthorized: Valid token required to set status to 'connected'"}), 401
        
        user.vscode_connected = True
        user.vscode_last_connected = datetime.datetime.now()
        db.session.commit() 
        app.logger.info("User '%s' VS Code Extension connection status updated to: Connected", user.username)
        socket.emit('vscode_status_update', 
                      {'status': 'connected', 'last_updated': user.vscode_last_connected.isoformat()}, 
                      room=str(user.id))
    elif status == 'disconnected':
        if user: 
            user.vscode_connected = False
            user.vscode_last_connected = datetime.datetime.now()
            db.session.commit() 
            app.logger.info("User '%s' VS Code Extension connection status updated to: Disconnected", user.username)
            socket.emit('vscode_status_update', 
                      {'status': 'disconnected', 'last_updated': user.vscode_last_connected.isoformat()}, 
                      room=str(user.id))
        else:
            app.logger.info("VS Code Extension sent 'disconnected' status, but no valid user token provided.")

    return jsonify({"message": "Connection status updated successfully"}), 200
     
@app.route('/api/get_connection_status', methods=['GET'])
@login_required # This ensures current_user is available
def get_connection_status():
    status = 'connected' if current_user.vscode_connected else 'disconnected'
    last_updated = current_user.vscode_last_connected.isoformat() if current_user.vscode_last_connected else None

    return jsonify({
        'status': status,
        'last_updated': last_updated
    }), 200

# ----- API Endpoint for SBOM Upload ----
@app.route('/api/upload_sbom', methods=['POST'])
@login_required
def upload_sbom():
    app.logger.info(f"Received SBOM upload request for user {current_user.username}")
    if 'sbom_file' not in request.files:
        return jsonify({"message": "No file part in the request"}), 400
    
    file = request.files['sbom_file']
    upload_type = request.form.get('upload_type')
    project_name = request.form.get('project_name', 'Unnamed Project')
    
    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400

    if upload_type not in ['zip_project', 'dependency_file', 'docker_tar', 'existing_sbom_json']:
        return jsonify({"message": "Invalid upload type"}), 400
    
    if not allowed_file(file.filename, upload_type):
        return jsonify({"message": f"Invalid file type for '{upload_type}'. Expected: {', '.join(ALLOWED_EXTENSIONS[upload_type])}"}), 400

    filename = secure_filename(file.filename)     
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path) 
    
    app.logger.info(f"File '{filename}' saved to {file_path} for user {current_user.username}")
    
    socket.start_background_task(
        target=perform_full_sbom_analysis,
        file_path=file_path,
        upload_type=upload_type,
        project_name=filename,
        user_id=current_user.id, 
        socketio_instance=socket,
        db_instance=db,          
        app_instance=app         
    )

    # Return immediate response to frontend
    return jsonify({"message": "SBOM processing started in background. Dashboard will update shortly."}), 202 # 202 Accepted
# ---------- Code Graph Parser ---------------------------
# @app.route('/api/analyze-zip', methods=['POST'])
# def analyze_zip_endpoint():
#     if 'sbom_file' not in request.files:
#         return jsonify({'error': 'No zip file provided.'}), 400
    
#     file = request.files['sbom_file']
#     code_parser.export_graph_data(file)
#     return jsonify(graph_data)

# ---- API for VScode Extension to fetch SBOM data ----
@app.route('/api/upload_sbom_from_extension', methods=['POST'])
def upload_sbom_from_extension():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"message": "Authorization header missing"}), 401

    try:
        token_type, token = auth_header.split(' ', 1)
        if token_type.lower() != 'bearer':
            return jsonify({"message": "Invalid token type, must be Bearer"}), 401
    except ValueError:
        return jsonify({"message": "Invalid Authorization header format"}), 401

    user = User.query.filter_by(personal_access_token=token).first()

    if not user or not user.is_pat_valid():
        return jsonify({"message": "Invalid or expired Personal Access Token"}), 401

    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400
    
    raw_sbom_json = request.get_json()
    project_name = request.args.get('project_name', 'Unnamed Project (Extension)') 
  

    if not raw_sbom_json:
        return jsonify({"message": "No SBOM JSON provided in request body"}), 400

    if isinstance(raw_sbom_json, dict) and 'sbomJson' in raw_sbom_json and isinstance(raw_sbom_json['sbomJson'], dict):
        app.logger.info("Unwrapping SBOM from 'sbomJson' key.")
        raw_sbom_json = raw_sbom_json['sbomJson']
    app.logger.info(f"Received SBOM JSON from extension for user {user.username}, project '{project_name}'.")

    temp_dir = 'uploads' 
    os.makedirs(temp_dir, exist_ok=True)
    temp_filename = f"sbom_extension_{user.id}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.json"
    filepath = os.path.join(temp_dir, temp_filename)
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(raw_sbom_json, f, indent=2)
        app.logger.info(f"SBOM JSON from extension saved temporarily to: {filepath}")

        socket.start_background_task(
            target=perform_full_sbom_analysis,
            file_path=filepath, 
            upload_type='existing_sbom_json',
            project_name=project_name,
            user_id=user.id, 
            socketio_instance=socket, 
            db_instance=db,             
            app_instance=app            
        )
        return jsonify({"message": "SBOM processing initiated successfully from extension!"}), 202
    except Exception as e:
        app.logger.error(f"Error processing SBOM from extension: {e}")
        return jsonify({"message": f"Server error during SBOM processing: {str(e)}"}), 500
    finally:
        # The finally block in perform_full_sbom_analysis will handle cleanup of this temp file
        pass

        
# ---- Update Dashboard with New SBOM Data ----
@app.route('/api/get_latest_sbom_data', methods=['GET'])
@login_required
def get_latest_sbom_data():
    latest_sbom = SBOM.query.filter_by(user_id=current_user.id).order_by(SBOM.timestamp.desc()).first()
    if latest_sbom:
        return jsonify({
            "components": latest_sbom.components_for_table,
            "license_chart": latest_sbom.license_chart_data,
            "project_name": latest_sbom.project_name,
            "sbom_timestamp": latest_sbom.timestamp.isoformat(),
            "vulnerability_chart": latest_sbom.vulnerability_chart_data,
            "dependency_chart": latest_sbom.dependency_chart_data
        }), 200
    return jsonify({
        "components": [],
        "license_chart": {"labels": [], "data": []},
        "project_name": "No SBOM Data",
        "sbom_timestamp": None,
        "vulnerability_chart": {"labels": ['Critical', 'High', 'Medium', 'Low', 'None'], "data": [0, 0, 0, 0, 0]},
        "dependency_chart": {"labels": ['Depth 1', 'Depth 2', 'Depth 3', 'Depth 4+'], "data": [0, 0, 0, 0]},
        "message": "No SBOMs found for this user."
    }), 200
    
@socket.on('connect')
def handle_connect():
    print(f"Socket.IO client connected. SID: {request.sid}")

@socket.on('disconnect')
def handle_disconnect():
    print(f"Socket.IO client disconnected. SID: {request.sid}")

@socket.on('join_user_room')
@login_required
def on_join_user_room(data):
    user_id = data.get('user_id')
    if user_id and str(user_id) == str(current_user.id):
        from flask_socketio import join_room
        join_room(str(user_id))
        print(f"User {current_user.username} (ID: {user_id}) joined Socket.IO room {user_id}")
    else:
        print(f"WARNING: Attempted to join room {user_id} with mismatching or missing user ID for current_user {current_user.id}")
@app.route("/sbom", methods=["GET"])
@login_required
def sbom_dasboard():
    return render_template('sbom_dasboard.html',user_id=current_user.id,title='SBOM Dashboard')


# ------------------ Linceance Compliance -----------------
@app.route('/licence_complicance')
@login_required
def licence_complicance():
    # ... your logic here
    return render_template('licence_complicance.html', title='License Compliance')
# ----------------------- Vulnerabiltiy Assessment page ---------------------------
@app.route('/vulnerability_assessment',methods=['GET'])
@login_required
def vulnerability_assessment():
    sbom_id = request.args.get('sbom_id', type=int)
    if not sbom_id:
        # Find the ID of the most recently uploaded SBOM
        latest_sbom = SBOM.query.filter_by(user_id=current_user.id).order_by(SBOM.timestamp.desc()).first()
        if latest_sbom:
            sbom_id = latest_sbom.id
        
    return render_template(
        'assessment.html',
        user_id=current_user.id,
        sbom_id=sbom_id, # Pass the ID to the frontend to fetch data
        title='Vulnerability Assessment'
    )

# ----------------------- Vulnerabiltiy Assessment API ---------------------------
@app.route('/api/vulnerability_details/<int:sbom_id>',methods=['GET'])
@login_required
def get_vulnerability_details(sbom_id):
    vuln_detail = db.session.query(VulnerabilityTable).join(SBOM).filter(
        SBOM.id == sbom_id,
        SBOM.user_id == current_user.id
    ).first()

    if not vuln_detail:
        return jsonify({"error": f"Vulnerability details not found for SBOM ID {sbom_id} or unauthorized."}), 404

    details = vuln_detail.vulnDetails
    if details is not None and isinstance(details, list):
        return jsonify(details), 200
    else:
        return jsonify({"error": "Vulnerability details are empty or not in the expected format (list)."}), 200

# ------ Graph retive api -------------
@app.route('/api/graph_data/<int:sbom_id>')
@login_required
def get_graph_data(sbom_id):
    vuln_entry = VulnerabilityTable.query.get(sbom_id)
    if not vuln_entry or vuln_entry.userID != current_user.id:
        return jsonify({'error': 'Graph data not found or unauthorized.'}), 404
    
    # graphData is already stored as a JSON-compatible Python structure
    return jsonify(vuln_entry.graphData)
with app.app_context():
    db.create_all() 
    
    if not User.query.filter_by(username='demo_user').first():
        demo_user = User(
            username='demo_user',
            email='demo_user@example.com'     # ⭐ ADD THIS
        )
        demo_user.set_password('password123')
        
        demo_user.vscode_connected = False
        demo_user.vscode_last_connected = None
        
        db.session.add(demo_user) 
        db.session.commit() 

        demo_user.generate_pat()
        print(f"Demo user 'demo_user' created with password 'password123' and PAT: {demo_user.personal_access_token}")
    else:
        print("Demo user 'demo_user' already exists.")
        existing_demo_user = User.query.filter_by(username='demo_user').first()
        if not existing_demo_user.personal_access_token or not existing_demo_user.is_pat_valid():
            existing_demo_user.generate_pat()
            print(f"Generated/Refreshed PAT for existing demo user: {existing_demo_user.personal_access_token}")
        
        if existing_demo_user.vscode_connected is None: 
            existing_demo_user.vscode_connected = False
            existing_demo_user.vscode_last_connected = None
            db.session.commit()



# --------- Reset Password--------- #

@app.route('/forget_password', methods=['GET', 'POST'])
def forget_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            send_reset_email(user)
            flash("Reset link sent to email", "info")
        else:
            flash("Email not found", "danger")

        return redirect(url_for('forget_password'))

    return render_template('forget_password.html')

@app.route('/forget_password/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    user = User.verify_reset_token(token)
    if not user:
        flash("Invalid or expired token", "danger")
        return redirect(url_for('forget_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')

        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(request.url)

        user.set_password(password)
        db.session.commit()

        flash("Password updated successfully", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')

def send_reset_email(user):
    token = user.get_reset_token()
    reset_url = url_for('reset_with_token', token=token, _external=True)

    msg = Message("SBOM Insights - Password Reset",
                  recipients=[user.email])
    msg.body = f"""
Hello {user.username},

To reset your password, click the link below:

{reset_url}

If you did not request this, you can safely ignore this email.

Regards,
SBOM Insights Team
"""

    mail.send(msg)


def get_reset_token(self, expires_sec=3600):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return s.dumps({"user_id": self.id})

@staticmethod
def verify_reset_token(token, expires_sec=3600):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        data = s.loads(token, max_age=expires_sec)
        return User.query.get(data["user_id"])
    except:
        return None




if __name__ == '__main__':
    socket.run(app,host='0.0.0.0',debug=True)