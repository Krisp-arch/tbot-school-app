import os
import json
import uuid
from functools import wraps
from collections import defaultdict
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError

# --- App Configuration & DB Setup ---
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

db_url = os.getenv('POSTGRES_URL')
if not db_url:
    raise ValueError("POSTGRES_URL environment variable not set.")
# SQLAlchemy 2.0 requires "postgresql://" instead of "postgres://"
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_recycle': 280} # Keep DB connections fresh
db = SQLAlchemy(app)

# --- Security & Admin Setup ---
PASSWORD_PEPPER = os.getenv('PASSWORD_PEPPER')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

# Critical check for security variables
if not all([app.secret_key, PASSWORD_PEPPER, ADMIN_EMAIL, ADMIN_PASSWORD]):
    raise ValueError("Missing critical security environment variables.")

# --- Database Models ---
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256))
    name = db.Column(db.String(100))
    role = db.Column(db.String(20), nullable=False, default='student')
    status = db.Column(db.String(20), nullable=False, default='active')
    def get_id(self): return self.email

class Mark(db.Model):
    __tablename__ = 'marks'
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=False)
    course_id_str = db.Column(db.String(80), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total = db.Column(db.Integer, nullable=False)

class Resource(db.Model):
    __tablename__ = 'resources'
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(120), unique=True, nullable=False)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)

class Course(db.Model):
    __tablename__ = 'courses'
    id = db.Column(db.Integer, primary_key=True)
    course_id_str = db.Column(db.String(80), unique=True, nullable=False)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.JSON, nullable=False)

# --- Login Manager & OAuth Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    if user_id == ADMIN_EMAIL:
        admin_user = User(id=0, email=ADMIN_EMAIL, name='System Admin', role='admin', status='active')
        return admin_user
    return User.query.filter_by(email=user_id, status='active').first()

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)
# --- Helper Functions ---
def hash_password(password): return generate_password_hash(password + PASSWORD_PEPPER)
def check_password(hashed, plain): return check_password_hash(hashed, plain + PASSWORD_PEPPER)
def get_badge(score):
    if score >= 95: return ('Top Tier', 'badge-scholar', '👑')
    if score >= 85: return ('Main Character', 'badge-achiever', '✨')
    if score >= 70: return ('Slay Queen', 'badge-distinction', '💅')
    if score >= 50: return ('Good Vibes', 'badge-merit', '💖')
    return ('Girl Boss in Training', 'badge-participant', '🌱')

# --- Decorators ---
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
        user_obj = None
        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            user_obj = load_user(ADMIN_EMAIL)
        else:
            user = User.query.filter_by(email=email).first()
            if user and user.password and check_password(user.password, password):
                if user.status == 'active': user_obj = user
                else: flash('Your account has been deactivated.', 'warning')
        if user_obj:
            login_user(user_obj)
            session.update(role=user_obj.role, name=user_obj.name, email=user_obj.email)
            return redirect(url_for('home'))
        flash('Invalid email or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('index'))

# --- ADD THESE TWO NEW ROUTES ---

@app.route('/login/google')
def google_login():
    """Redirects to Google's authorization page."""
    # The URL Google will redirect back to after login
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    """Callback function for Google OAuth."""
    token = google.authorize_access_token()
    # The user's info is in the 'userinfo' part of the token
    user_info = token.get('userinfo')
    if not user_info:
        flash("Authentication failed.", "danger")
        return redirect(url_for('login'))

    user_email = user_info['email']
    user_name = user_info['name']

    # Find user in our database
    user = User.query.filter_by(email=user_email).first()

    # If user doesn't exist, create a new one
    if not user:
        user = User(
            email=user_email,
            name=user_name,
            role='student', # New users default to 'student'
            status='active'
        )
        db.session.add(user)
        db.session.commit()
        flash("Welcome! Your account has been created.", "success")
    
    # Log the user in
    login_user(user)
    session.update(role=user.role, name=user.name, email=user.email)
    return redirect(url_for('home'))

# --- END OF NEW ROUTES ---

@app.route('/home')
@login_required
def home():
    if current_user.role == 'admin': return redirect(url_for('admin_dashboard'))
    user_marks = Mark.query.filter_by(user_email=current_user.email).all()
    all_courses = Course.query.order_by(Course.title).all()
    all_resources = Resource.query.order_by(Resource.title).all()
    # CHANGE IS HERE: Pass the course objects directly
    return render_template('home.html', courses=all_courses, marks=user_marks, resources=all_resources)

@app.route('/resource/<slug>')
@login_required
def resource_page(slug):
    resource = Resource.query.filter_by(slug=slug).first_or_404()
    return render_template('resource_page.html', resource=resource)

@app.route('/course/<course_id_str>')
@login_required
def course_page(course_id_str):
    course = Course.query.filter_by(course_id_str=course_id_str).first_or_404()
    return render_template('course.html', course=course.content)

@app.route('/submit_quiz/<course_id_str>', methods=['POST'])
@login_required
def submit_quiz(course_id_str):
    course = Course.query.filter_by(course_id_str=course_id_str).first_or_404().content
    score = sum(1 for q in course['quiz'] if request.form.get(f'question_{q["id"]}') == str(q['answer']))
    total = len(course['quiz'])
    new_mark = Mark(user_email=current_user.email, course_id_str=course_id_str, score=score, total=total)
    db.session.add(new_mark)
    db.session.commit()
    flash(f"Quiz submitted! You scored {score}/{total}.", "success")
    # simplified quiz result display logic
    return redirect(url_for('home'))

@app.route('/toppers')
@login_required
def toppers():
    # Step 1: Find the highest score for each user on each unique course quiz.
    # This subquery gives us rows like (user_email, course_id_str, max_score, total_for_that_quiz)
    highest_scores_per_quiz = db.session.query(
        Mark.user_email,
        Mark.course_id_str,
        func.max(Mark.score).label('max_score'),
        Mark.total.label('total')
    ).group_by(Mark.user_email, Mark.course_id_str, Mark.total).subquery()

    # Step 2: Sum up these highest scores and totals for each user.
    # This gives us the final aggregate totals we need.
    scores_q = db.session.query(
        highest_scores_per_quiz.c.user_email,
        func.sum(highest_scores_per_quiz.c.max_score).label('ts'),
        func.sum(highest_scores_per_quiz.c.total).label('tp')
    ).group_by(highest_scores_per_quiz.c.user_email).subquery()

    # Step 3: Join with the User table to get names (this part stays the same).
    toppers_data = db.session.query(
        User.name,
        scores_q.c.ts,
        scores_q.c.tp
    ).join(scores_q, User.email == scores_q.c.user_email).all()

    # Step 4: Process the data for the template (this part stays the same).
    topper_list = []
    for name, total_score, total_possible in toppers_data:
        if total_possible > 0:
            avg_score = (total_score / total_possible) * 100
            badge_name, badge_class, badge_icon = get_badge(avg_score)
            topper_list.append({
                'name': name,
                'average_score': avg_score,
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
    stats = {'users': User.query.count(), 'courses': Course.query.count(), 'resources': Resource.query.count()}
    return render_template('admin/dashboard.html', num_users=stats['users'], num_courses=stats['courses'], num_resources=stats['resources'])

# --- User Management ---
@app.route('/admin/manage_users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    if request.method == 'POST':
        email, password = request.form.get('email'), request.form.get('password')
        if not password: flash("Password is required for new users.", "danger")
        else:
            new_user = User(email=email, password=hash_password(password), name=request.form['name'], role=request.form['role'])
            db.session.add(new_user)
            try:
                db.session.commit()
                flash(f"User {new_user.name} added successfully.", "success")
            except IntegrityError:
                db.session.rollback()
                flash(f"User with email {email} already exists.", "danger")
        return redirect(url_for('manage_users'))
    users = User.query.order_by(User.name).all()
    return render_template('admin/manage_users.html', users=users)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.name, user.role = request.form['name'], request.form['role']
        if new_pass := request.form.get('password'): user.password = hash_password(new_pass)
        db.session.commit()
        flash(f"User {user.name}'s details updated.", "success")
        return redirect(url_for('manage_users'))
    return render_template('admin/edit_user.html', user=user)

@app.route('/admin/toggle_user_status/<int:user_id>')
@admin_required
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)
    if user.email == current_user.email: flash("You cannot change your own status.", "danger")
    else:
        user.status = 'inactive' if user.status == 'active' else 'active'
        db.session.commit()
        flash(f"User {user.name} has been set to {user.status}.", "success")
    return redirect(url_for('manage_users'))

# --- Resource Management ---
@app.route('/admin/resources')
@admin_required
def manage_resources():
    return render_template('admin/manage_resources.html', resources=Resource.query.order_by(Resource.title).all())

@app.route('/admin/resources/add', methods=['POST'])
@admin_required
def add_resource():
    title = request.form.get('title')
    slug = title.lower().replace(' ', '-').replace('/', '') if title else ''
    if not slug: flash("Title is required.", "danger")
    else:
        new_res = Resource(slug=slug, title=title, content="<p>Start writing your content here!</p>")
        db.session.add(new_res)
        try:
            db.session.commit()
            flash("New resource page created.", "success")
            return redirect(url_for('edit_resource', resource_id=new_res.id))
        except IntegrityError:
            db.session.rollback()
            flash("A resource with this title/slug already exists.", "danger")
    return redirect(url_for('manage_resources'))

@app.route('/admin/resources/edit/<int:resource_id>', methods=['GET', 'POST'])
@admin_required
def edit_resource(resource_id):
    resource = Resource.query.get_or_404(resource_id)
    if request.method == 'POST':
        resource.title = request.form['title']
        resource.content = request.form['content']
        db.session.commit()
        flash("Resource page updated successfully!", "success")
        return redirect(url_for('manage_resources'))
    return render_template('admin/edit_resource.html', resource=resource)

# --- Course Management ---
@app.route('/admin/courses')
@admin_required
def manage_courses():
    courses = Course.query.order_by(Course.title).all()
    return render_template('admin/manage_courses.html', courses=courses)


@app.route('/admin/courses/edit/<int:course_id>', methods=['GET', 'POST'])
@admin_required
def edit_course(course_id):
    course = Course.query.get_or_404(course_id)
    if request.method == 'POST':
        try:
            content = json.loads(request.form['json_content'])
            course.course_id_str = content['id']
            course.title = content.get('title', 'Untitled')
            course.content = content
            db.session.commit()
            flash(f"Course '{course.title}' updated successfully.", "success")
            return redirect(url_for('manage_courses'))
        except (json.JSONDecodeError, KeyError) as e:
            flash(f"Invalid JSON or missing 'id' field. Error: {e}", "danger")
        except IntegrityError:
            db.session.rollback()
            flash(f"A course with ID '{content['id']}' already exists.", "danger")
    
    # For the GET request, show the pretty-printed JSON
    pretty_json = json.dumps(course.content, indent=4)
    return render_template('admin/edit_course.html', course=course, content=pretty_json)

@app.route('/admin/courses/delete/<int:course_id>')
@admin_required
def delete_course(course_id):
    course = Course.query.get_or_404(course_id)
    db.session.delete(course)
    db.session.commit()
    flash(f"Course '{course.title}' has been deleted.", "success")
    return redirect(url_for('manage_courses'))
    
    
    
@app.route('/admin/add_course', methods=['GET', 'POST'])
@admin_required
def add_course():
    if request.method == 'POST':
        try:
            content = json.loads(request.form['json_content'])
            course_id_str = content['id']
            new_course = Course(course_id_str=course_id_str, title=content.get('title', 'Untitled'), content=content)
            db.session.add(new_course)
            db.session.commit()
            flash(f"Course '{new_course.title}' added.", "success")
            return redirect(url_for('admin_dashboard'))
        except (json.JSONDecodeError, KeyError) as e:
            flash(f"Invalid JSON or missing 'id' field. Error: {e}", "danger")
        except IntegrityError:
            db.session.rollback()
            flash(f"A course with ID '{course_id_str}' already exists.", "danger")
        return render_template('admin/add_course.html', content=request.form.get('json_content', ''))
    return render_template('admin/add_course.html')

# --- App Initializer ---
# This block will run on Vercel during the build and create the tables.
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)