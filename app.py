import os
import csv
import json
import uuid
from functools import wraps
from collections import defaultdict
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# --- App Configuration ---
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'a-very-secret-and-secure-key-for-tbot')

# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
)

class User(UserMixin):
    def __init__(self, id, email, name, role='student', status='active'):
        self.id = id
        self.email = email
        self.name = name
        self.role = role
        self.status = status

    @staticmethod
    def get(user_id):
        users = get_users()
        user_data = next((u for u in users if u['email'] == user_id), None)
        if user_data:
            # Check if user is active
            if user_data.get('status', 'active') == 'inactive':
                return None
            return User(id=user_data['email'], email=user_data['email'], 
                       name=user_data.get('name', ''), role=user_data.get('role', 'student'),
                       status=user_data.get('status', 'active'))
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# --- Data File Paths ---
DATA_DIR = 'data'
USERS_FILE = os.path.join(DATA_DIR, 'users.csv')
MARKS_FILE = os.path.join(DATA_DIR, 'student_marks.csv')
COURSES_DIR = os.path.join(DATA_DIR, 'courses')
RESOURCES_DIR = os.path.join(DATA_DIR, 'resources')
USER_FIELDNAMES = ['email', 'password', 'name', 'role', 'status']

# --- Helper Functions for Data Handling ---

def get_users():
    if not os.path.exists(USERS_FILE): return []
    with open(USERS_FILE, mode='r', newline='') as f:
        return list(csv.DictReader(f))

def save_users(users):
    with open(USERS_FILE, mode='w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=USER_FIELDNAMES)
        writer.writeheader()
        writer.writerows(users)

# ... (rest of helper functions for courses, marks, resources) ...
def get_courses():
    courses = []
    if not os.path.exists(COURSES_DIR): return []
    for filename in os.listdir(COURSES_DIR):
        if filename.endswith('.json'):
            with open(os.path.join(COURSES_DIR, filename), 'r') as f:
                courses.append(json.load(f))
    return courses

def get_course_by_id(course_id):
    filepath = os.path.join(COURSES_DIR, f"{course_id}.json")
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return json.load(f)
    return None

def get_marks():
    if not os.path.exists(MARKS_FILE): return []
    with open(MARKS_FILE, mode='r', newline='') as f:
        return list(csv.DictReader(f))

def add_mark(email, course_id, score, total):
    fieldnames = ['email', 'course_id', 'score', 'total']
    file_exists = os.path.exists(MARKS_FILE)
    write_header = not file_exists or os.path.getsize(MARKS_FILE) == 0
    with open(MARKS_FILE, mode='a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        writer.writerow({'email': email, 'course_id': course_id, 'score': score, 'total': total})

def get_resources():
    resources = []
    if not os.path.exists(RESOURCES_DIR): return []
    for filename in os.listdir(RESOURCES_DIR):
        if filename.endswith('.json'):
            filepath = os.path.join(RESOURCES_DIR, filename)
            try:
                with open(filepath, 'r') as f:
                    resources.append(json.load(f))
            except json.JSONDecodeError:
                print(f"WARNING: Could not decode JSON from file: {filename}. Skipping.")
                continue
    return resources

def get_resource(slug):
    filepath = os.path.join(RESOURCES_DIR, f"{slug}.json")
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return json.load(f)
    return None

def save_resource(data):
    filepath = os.path.join(RESOURCES_DIR, f"{data['slug']}.json")
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)

def get_badge(score):
    if score >= 95: return ('Top Tier', 'badge-scholar', '👑')
    if score >= 85: return ('Main Character', 'badge-achiever', '✨')
    if score >= 70: return ('Slay Queen', 'badge-distinction', '💅')
    if score >= 50: return ('Good Vibes', 'badge-merit', '💖')
    return ('Girl Boss in Training', 'badge-participant', '🌱')

# --- Decorators for Authentication ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# --- Main Routes ---
@app.route('/')
def index():
    if current_user.is_authenticated: return redirect(url_for('home'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        users = get_users()
        user_data = next((u for u in users if u['email'] == email and u['password'] == password), None)
        
        if user_data:
            # Check if the user is active before logging in
            if user_data.get('status') == 'inactive':
                flash('Your account has been deactivated. Please contact an administrator.', 'warning')
                return redirect(url_for('login'))
            
            user_obj = User.get(user_data['email'])
            if user_obj:
                login_user(user_obj)
                session['role'] = user_obj.role
                session['name'] = user_obj.name
                session['email'] = user_obj.email
                return redirect(url_for('home'))
        
        flash('Invalid email or password', 'error')
    return render_template('login.html')

@app.route('/login/google')
def google_login():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    
    users = get_users()
    user_data = next((u for u in users if u['email'] == user_info['email']), None)
    
    if not user_data:
        new_user = {
            'email': user_info['email'],
            'password': generate_password_hash(str(uuid.uuid4())),
            'name': user_info.get('name', user_info['email'].split('@')[0]),
            'role': 'student',
            'status': 'active' # New users are active by default
        }
        users.append(new_user)
        save_users(users)
        user_data = new_user

    if user_data.get('status') == 'inactive':
        flash('Your account has been deactivated. Please contact an administrator.', 'warning')
        return redirect(url_for('login'))
        
    user_obj = User.get(user_data['email'])
    if user_obj:
        login_user(user_obj)
        session['role'] = user_obj.role
        session['name'] = user_obj.name
        session['email'] = user_obj.email
        return redirect(url_for('home'))
    
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('index'))

@app.route('/home')
@login_required
def home():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    user_marks = [mark for mark in get_marks() if mark['email'] == current_user.email]
    resources = get_resources()
    return render_template('home.html', hsc_info=get_courses(), marks=user_marks, resources=resources)

# ... (other main routes: resource_page, course_page, submit_quiz, toppers) ...
@app.route('/resource/<slug>')
@login_required
def resource_page(slug):
    resource = get_resource(slug)
    if not resource:
        flash("Sorry, that resource page could not be found.", "danger")
        return redirect(url_for('home'))
    return render_template('resource_page.html', resource=resource)
    
@app.route('/course/<course_id>')
@login_required
def course_page(course_id):
    course = get_course_by_id(course_id)
    if not course: return redirect(url_for('home'))
    return render_template('course.html', course=course)

@app.route('/submit_quiz/<course_id>', methods=['POST'])
@login_required
def submit_quiz(course_id):
    course = get_course_by_id(course_id)
    if not course: return redirect(url_for('home'))
    score = 0
    total = len(course['quiz'])
    user_answers = {}
    for i, q in enumerate(course['quiz']):
        user_answer = request.form.get(f'question_{i}')
        user_answers[q['question']] = user_answer
        if user_answer == q['answer']:
            score += 1
    add_mark(current_user.email, course_id, score, total)
    flash(f"Quiz submitted! You scored {score}/{total}.", "success")
    return render_template('quiz_result.html', 
                           score=score, total=total, course=course, user_answers=user_answers)

@app.route('/toppers')
@login_required
def toppers():
    user_map = {user['email']: user['name'] for user in get_users()}
    student_scores = defaultdict(lambda: {'total_scored': 0, 'total_possible': 0})
    for mark in get_marks():
        email = mark.get('email')
        if email:
            student_scores[email]['total_scored'] += int(mark.get('score', 0))
            student_scores[email]['total_possible'] += int(mark.get('total', 0))
    topper_list = []
    for email, scores in student_scores.items():
        if scores['total_possible'] > 0:
            average = (scores['total_scored'] / scores['total_possible']) * 100
            badge_name, badge_class, badge_icon = get_badge(average)
            topper_list.append({
                'name': user_map.get(email, 'Unknown'),
                'average_score': round(average, 2),
                'badge_name': badge_name,
                'badge_class': badge_class,
                'badge_icon': badge_icon
            })
    topper_list.sort(key=lambda x: x['average_score'], reverse=True)
    return render_template('toppers.html', toppers=topper_list)

# --- Admin Routes ---
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    num_users = len(get_users())
    num_courses = len(get_courses())
    num_resources = len(get_resources())
    return render_template('admin/dashboard.html', 
                           num_users=num_users, num_courses=num_courses, num_resources=num_resources)

# MODIFIED: User management now cleaner and more powerful
@app.route('/admin/manage_users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    if request.method == 'POST':
        email = request.form.get('email')
        users = get_users()
        # Check for unique email before adding
        if any(u['email'] == email for u in users):
            flash(f"User with email {email} already exists.", "danger")
        else:
            new_user = {
                'email': email,
                'password': request.form['password'],
                'name': request.form['name'],
                'role': request.form['role'],
                'status': 'active'
            }
            users.append(new_user)
            save_users(users)
            flash(f"User {request.form['name']} added successfully.", "success")
        return redirect(url_for('manage_users'))

    users = get_users()
    return render_template('admin/manage_users.html', users=users)

# NEW: Route to edit a user
@app.route('/admin/edit_user/<user_email>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_email):
    users = get_users()
    user_to_edit = next((u for u in users if u['email'] == user_email), None)

    if not user_to_edit:
        flash("User not found.", "danger")
        return redirect(url_for('manage_users'))

    if request.method == 'POST':
        user_to_edit['name'] = request.form['name']
        user_to_edit['role'] = request.form['role']
        # Optionally reset password
        new_password = request.form.get('password')
        if new_password:
            user_to_edit['password'] = new_password
        
        save_users(users)
        flash(f"User {user_to_edit['name']}'s details updated.", "success")
        return redirect(url_for('manage_users'))

    return render_template('admin/edit_user.html', user=user_to_edit)

# NEW: Route to toggle user status (activate/inactivate)
@app.route('/admin/toggle_user_status/<user_email>')
@admin_required
def toggle_user_status(user_email):
    users = get_users()
    user_to_toggle = next((u for u in users if u['email'] == user_email), None)

    if user_to_toggle:
        # Prevent admin from deactivating themselves
        if user_to_toggle['email'] == current_user.email:
             flash("You cannot change your own status.", "danger")
        else:
            current_status = user_to_toggle.get('status', 'active')
            new_status = 'inactive' if current_status == 'active' else 'active'
            user_to_toggle['status'] = new_status
            save_users(users)
            flash(f"User {user_to_toggle['name']} has been set to {new_status}.", "success")
    
    return redirect(url_for('manage_users'))

# ... (other admin routes: resources, add_course) ...
@app.route('/admin/resources')
@admin_required
def manage_resources():
    return render_template('admin/manage_resources.html', resources=get_resources())

@app.route('/admin/resources/add', methods=['POST'])
@admin_required
def add_resource():
    title = request.form.get('title')
    slug = title.lower().replace(' ', '-').replace('/', '')
    if not title or get_resource(slug):
        flash("Title is required or a resource with a similar title already exists.", "danger")
        return redirect(url_for('manage_resources'))
    new_resource = { "slug": slug, "title": title, "content": "<p>Start writing your content here!</p>" }
    save_resource(new_resource)
    flash("New resource page created. You can now edit it.", "success")
    return redirect(url_for('edit_resource', slug=slug))

@app.route('/admin/resources/edit/<slug>', methods=['GET', 'POST'])
@admin_required
def edit_resource(slug):
    resource = get_resource(slug)
    if not resource: return redirect(url_for('manage_resources'))
    if request.method == 'POST':
        resource['title'] = request.form['title']
        resource['content'] = request.form['content']
        save_resource(resource)
        flash("Resource page updated successfully!", "success")
        return redirect(url_for('manage_resources'))
    return render_template('admin/edit_resource.html', resource=resource)

@app.route('/admin/add_course', methods=['GET', 'POST'])
@admin_required
def add_course():
    if request.method == 'POST':
        try:
            course_data = json.loads(request.form['json_content'])
            course_id = course_data['id']
            with open(os.path.join(COURSES_DIR, f"{course_id}.json"), 'w') as f:
                json.dump(course_data, f, indent=4)
            flash(f"Course '{course_data.get('title')}' added.", "success")
            return redirect(url_for('admin_dashboard'))
        except (json.JSONDecodeError, KeyError):
            flash("Invalid JSON or missing 'id' field.", "danger")
            return render_template('admin/add_course.html', content=request.form['json_content'])
    return render_template('admin/add_course.html')

# --- Run the App ---
if __name__ == '__main__':
    for d in [DATA_DIR, COURSES_DIR, RESOURCES_DIR]:
        os.makedirs(d, exist_ok=True)
    app.run(debug=True)