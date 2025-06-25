import os
import csv
import json
import uuid
from functools import wraps
from collections import defaultdict
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash ### --- MODIFIED --- ###
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# --- App Configuration ---
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') ### --- MODIFIED: Use a real secret key --- ###

### --- NEW: Load security variables --- ###
PASSWORD_PEPPER = os.getenv('PASSWORD_PEPPER')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

# Critical check to ensure security variables are set
if not all([app.secret_key, PASSWORD_PEPPER, ADMIN_EMAIL, ADMIN_PASSWORD]):
    raise ValueError("Missing critical environment variables: SECRET_KEY, PASSWORD_PEPPER, ADMIN_EMAIL, ADMIN_PASSWORD")

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

# --- Helper Functions for Data and Security --- ### --- MODIFIED SECTION --- ###

def hash_password(password):
    """Hashes a password with the application's pepper."""
    return generate_password_hash(password + PASSWORD_PEPPER)

def check_password(hashed_password, provided_password):
    """Checks a provided password against a hash, using the application's pepper."""
    return check_password_hash(hashed_password, provided_password + PASSWORD_PEPPER)

def get_users():
    """Reads users from CSV and injects the environment-defined admin user."""
    users = []
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, mode='r', newline='') as f:
            users = list(csv.DictReader(f))
    
    # Inject the admin user from environment variables. This user cannot be edited in the UI.
    admin_user = {
        'email': ADMIN_EMAIL,
        'password': hash_password(ADMIN_PASSWORD), # Store it hashed in memory for consistency
        'name': 'System Admin',
        'role': 'admin',
        'status': 'active'
    }
    # Ensure admin is not duplicated if their email somehow ended up in the CSV
    users = [u for u in users if u['email'] != ADMIN_EMAIL]
    users.insert(0, admin_user)
    return users

def save_users(users):
    """Saves users to CSV, filtering out the environment-defined admin user."""
    # Never write the environment admin user to the CSV file
    users_to_save = [u for u in users if u['email'] != ADMIN_EMAIL]
    with open(USERS_FILE, mode='w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=USER_FIELDNAMES)
        writer.writeheader()
        writer.writerows(users_to_save)

# ... (rest of helper functions for courses, marks, resources are unchanged) ...
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
        user_data = next((u for u in users if u['email'] == email), None)
        
        ### --- MODIFIED: Use hashed password check --- ###
        if user_data and check_password(user_data['password'], password):
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
        # For Google sign-ups, generate a long random password as it won't be used for direct login
        new_user = {
            'email': user_info['email'],
            'password': hash_password(str(uuid.uuid4())), ### --- MODIFIED --- ###
            'name': user_info.get('name', user_info['email'].split('@')[0]),
            'role': 'student',
            'status': 'active'
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

# ... (Home, resource, course, quiz, toppers routes are unchanged) ...
@app.route('/home')
@login_required
def home():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    user_marks = [mark for mark in get_marks() if mark['email'] == current_user.email]
    resources = get_resources()
    return render_template('home.html', hsc_info=get_courses(), marks=user_marks, resources=resources)

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
    # Subtract 1 to not count the virtual admin user in the stats
    num_users = len(get_users()) - 1 
    num_courses = len(get_courses())
    num_resources = len(get_resources())
    return render_template('admin/dashboard.html', 
                           num_users=num_users, num_courses=num_courses, num_resources=num_resources)

@app.route('/admin/manage_users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        users = get_users()
        
        if not password:
            flash("Password is required for new users.", "danger")
            return redirect(url_for('manage_users'))
            
        if any(u['email'] == email for u in users):
            flash(f"User with email {email} already exists.", "danger")
        else:
            new_user = {
                'email': email,
                'password': hash_password(password), ### --- MODIFIED --- ###
                'name': request.form['name'],
                'role': request.form['role'],
                'status': 'active'
            }
            # The get_users() list already includes the admin, so we need to save without it.
            # save_users() handles this filtering automatically.
            csv_users = [u for u in users if u['email'] != ADMIN_EMAIL]
            csv_users.append(new_user)
            save_users(csv_users)
            flash(f"User {request.form['name']} added successfully.", "success")
        return redirect(url_for('manage_users'))

    # Filter out the system admin so they cannot be edited from the UI
    display_users = [u for u in get_users() if u['email'] != ADMIN_EMAIL]
    return render_template('admin/manage_users.html', users=display_users)


@app.route('/admin/edit_user/<user_email>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_email):
    # Prevent editing the system admin via URL manipulation
    if user_email == ADMIN_EMAIL:
        flash("The system admin user cannot be edited from the UI.", "danger")
        return redirect(url_for('manage_users'))
        
    users = get_users()
    user_to_edit_list = [u for u in users if u['email'] == user_email]

    if not user_to_edit_list:
        flash("User not found.", "danger")
        return redirect(url_for('manage_users'))
    
    user_to_edit = user_to_edit_list[0]

    if request.method == 'POST':
        user_to_edit['name'] = request.form['name']
        user_to_edit['role'] = request.form['role']
        new_password = request.form.get('password')
        if new_password:
            user_to_edit['password'] = hash_password(new_password) ### --- MODIFIED --- ###
        
        save_users(users)
        flash(f"User {user_to_edit['name']}'s details updated.", "success")
        return redirect(url_for('manage_users'))

    return render_template('admin/edit_user.html', user=user_to_edit)


@app.route('/admin/toggle_user_status/<user_email>')
@admin_required
def toggle_user_status(user_email):
    # Prevent deactivating the system admin
    if user_email == ADMIN_EMAIL:
        flash("The system admin user cannot be deactivated.", "danger")
        return redirect(url_for('manage_users'))

    users = get_users()
    user_to_toggle = next((u for u in users if u['email'] == user_email), None)

    if user_to_toggle:
        # Prevent admin from deactivating themselves (redundant check, but good practice)
        if user_to_toggle['email'] == current_user.email:
             flash("You cannot change your own status.", "danger")
        else:
            current_status = user_to_toggle.get('status', 'active')
            new_status = 'inactive' if current_status == 'active' else 'active'
            user_to_toggle['status'] = new_status
            save_users(users)
            flash(f"User {user_to_toggle['name']} has been set to {new_status}.", "success")
    
    return redirect(url_for('manage_users'))

# ... (other admin routes: resources, add_course are unchanged) ...
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