from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os
from datetime import datetime
import uuid
import shutil
from functools import wraps
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'uploads')
app.config['RECAPTCHA_SITE_KEY'] = os.environ.get('RECAPTCHA_SITE_KEY', '6LfNleIqAAAAADTRvsuzE4ikRTsSQjgi-yRp3S-G')
app.config['RECAPTCHA_SECRET_KEY'] = os.environ.get('RECAPTCHA_SECRET_KEY', '6LfNleIqAAAAABAgZYk6Le5k1AITiqpCIeutqbIv')

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Generate encryption key
key = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
cipher_suite = Fernet(key)

# Admin credentials from environment variables
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin@123!')

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Access denied. Admin privileges required.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    files = db.relationship('EncryptedFile', backref='owner', lazy=True)

class EncryptedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=False)  # Stores the encrypted file's name
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

def verify_recaptcha(response_token):
    data = {
        'secret': app.config['RECAPTCHA_SECRET_KEY'],
        'response': response_token
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
    return response.json().get('success', False)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Verify reCAPTCHA
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not verify_recaptcha(recaptcha_response):
            flash('Please complete the reCAPTCHA verification')
            return redirect(url_for('login'))
            
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        flash('Invalid username or password')
    return render_template('login.html', site_key=app.config['RECAPTCHA_SITE_KEY'])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Verify reCAPTCHA
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not verify_recaptcha(recaptcha_response):
            flash('Please complete the reCAPTCHA verification')
            return redirect(url_for('register'))
            
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username.lower() == ADMIN_USERNAME:
            flash('This username is reserved')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', site_key=app.config['RECAPTCHA_SITE_KEY'])

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    files = EncryptedFile.query.all()
    return render_template('admin_dashboard.html', files=files)

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    files = EncryptedFile.query.filter_by(user_id=current_user.id).all()
    return render_template('user_dashboard.html', files=files)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    
    if file:
        # Generate unique filename for encrypted file
        original_filename = file.filename
        encrypted_filename = f"{uuid.uuid4().hex}.enc"
        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        
        # Read and encrypt file
        file_data = file.read()
        encrypted_data = cipher_suite.encrypt(file_data)
        
        # Save encrypted file
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Store file metadata in database
        encrypted_file = EncryptedFile(
            filename=original_filename,
            encrypted_filename=encrypted_filename,
            user_id=current_user.id
        )
        db.session.add(encrypted_file)
        db.session.commit()
        flash('File uploaded and encrypted successfully')
    
    return redirect(url_for('user_dashboard'))

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    encrypted_file = EncryptedFile.query.get_or_404(file_id)
    if not current_user.is_admin and encrypted_file.user_id != current_user.id:
        flash('Access denied')
        return redirect(url_for('index'))
    
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_file.encrypted_filename)
    
    # Read and decrypt file
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()
    
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    
    # Create a temporary file with the original filename
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{encrypted_file.filename}")
    with open(temp_path, 'wb') as f:
        f.write(decrypted_data)
    
    # Send the file and delete the temporary file after sending
    response = send_file(
        temp_path,
        as_attachment=True,
        download_name=encrypted_file.filename
    )
    
    # Delete the temporary file after sending
    @response.call_on_close
    def cleanup():
        try:
            os.remove(temp_path)
        except:
            pass
    
    return response

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

def create_admin_user():
    admin = User.query.filter_by(username=ADMIN_USERNAME).first()
    if not admin:
        admin = User(
            username=ADMIN_USERNAME,
            password_hash=generate_password_hash(ADMIN_PASSWORD),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
    else:
        if not check_password_hash(admin.password_hash, ADMIN_PASSWORD):
            admin.password_hash = generate_password_hash(ADMIN_PASSWORD)
            db.session.commit()

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.filter(User.username != ADMIN_USERNAME).all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == ADMIN_USERNAME:
        flash('Cannot delete admin user')
        return redirect(url_for('admin_users'))
    
    # Delete user's files from storage
    files = EncryptedFile.query.filter_by(user_id=user_id).all()
    for file in files:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file.encrypted_filename))
        except:
            pass
    
    # Delete user and their file records from database
    EncryptedFile.query.filter_by(user_id=user_id).delete()
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {user.username} and all their data have been deleted')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/<int:user_id>/change_password', methods=['POST'])
@login_required
@admin_required
def change_user_password(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == ADMIN_USERNAME:
        flash('Cannot change admin password')
        return redirect(url_for('admin_users'))
    
    new_password = request.form.get('new_password')
    if not new_password:
        flash('Password cannot be empty')
        return redirect(url_for('admin_users'))
    
    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    flash(f'Password changed for user {user.username}')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/<int:user_id>/files')
@login_required
@admin_required
def user_files(user_id):
    user = User.query.get_or_404(user_id)
    files = EncryptedFile.query.filter_by(user_id=user_id).all()
    return render_template('user_files.html', user=user, files=files)

@app.route('/admin/file/<int:file_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_file(file_id):
    encrypted_file = EncryptedFile.query.get_or_404(file_id)
    
    # Delete the actual file
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], encrypted_file.encrypted_filename))
    except:
        pass
    
    # Delete the database record
    db.session.delete(encrypted_file)
    db.session.commit()
    
    flash('File deleted successfully')
    return redirect(url_for('user_files', user_id=encrypted_file.user_id))

@app.route('/admin/create', methods=['POST'])
@login_required
@admin_required
def create_admin():
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    
    if not username or not password or not confirm_password:
        flash('All fields are required')
        return redirect(url_for('admin_dashboard'))
    
    if password != confirm_password:
        flash('Passwords do not match')
        return redirect(url_for('admin_dashboard'))
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists')
        return redirect(url_for('admin_dashboard'))
    
    new_admin = User(
        username=username,
        password_hash=generate_password_hash(password),
        is_admin=True
    )
    
    db.session.add(new_admin)
    db.session.commit()
    
    flash(f'Admin user {username} created successfully')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
    app.run(debug=True) 