# app.py - Main Flask application
import os
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['DATABASE'] = 'internship.db'

# Initialize database
def init_db():
    with sqlite3.connect(app.config['DATABASE']) as conn:
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student', 'company', 'admin')),
            name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create profiles table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            skills TEXT,
            education TEXT,
            experience TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Create internships table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS internships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            required_skills TEXT,
            posted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (company_id) REFERENCES users (id)
        )
        ''')
        
        # Create applications table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            internship_id INTEGER NOT NULL,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending',
            FOREIGN KEY (student_id) REFERENCES users (id),
            FOREIGN KEY (internship_id) REFERENCES internships (id)
        )
        ''')
        
        # Create messages table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            internship_id INTEGER NOT NULL,
            content TEXT,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (receiver_id) REFERENCES users (id),
            FOREIGN KEY (internship_id) REFERENCES internships (id)
        )
        ''')
        
        # Create admin user if not exists
        cursor.execute("SELECT * FROM users WHERE email=?", ('admin@internhub.com',))
        admin = cursor.fetchone()
        if not admin:
            hashed_pw = generate_password_hash('admin123')
            cursor.execute("INSERT INTO users (email, password, role, name) VALUES (?, ?, ?, ?)", 
                           ('admin@internhub.com', hashed_pw, 'admin', 'Admin User'))
        
        # Create sample data for demonstration
        cursor.execute("SELECT * FROM users WHERE role='student'")
        if not cursor.fetchone():
            hashed_pw = generate_password_hash('student123')
            cursor.execute("INSERT INTO users (email, password, role, name) VALUES (?, ?, ?, ?)", 
                           ('student@example.com', hashed_pw, 'student', 'John Doe'))
            student_id = cursor.lastrowid
            cursor.execute("INSERT INTO profiles (user_id, skills, education, experience) VALUES (?, ?, ?, ?)",
                           (student_id, 'Python, Flask, SQL', 'Computer Science BSc', 'Part-time web developer'))
            
        cursor.execute("SELECT * FROM users WHERE role='company'")
        if not cursor.fetchone():
            hashed_pw = generate_password_hash('company123')
            cursor.execute("INSERT INTO users (email, password, role, name) VALUES (?, ?, ?, ?)", 
                           ('company@example.com', hashed_pw, 'company', 'TechCorp Inc'))
            company_id = cursor.lastrowid
            cursor.execute("INSERT INTO internships (company_id, title, description, required_skills) VALUES (?, ?, ?, ?)",
                           (company_id, 'Web Development Intern', 'Develop web applications using Flask', 'Python, Flask, HTML, CSS'))
            cursor.execute("INSERT INTO internships (company_id, title, description, required_skills) VALUES (?, ?, ?, ?)",
                           (company_id, 'Data Science Intern', 'Analyze datasets and build ML models', 'Python, Pandas, Machine Learning'))
        
        conn.commit()

# Database connection helper
def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

# Authentication routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        name = request.form.get('name', '')
        
        if not email or not password or not role:
            flash('Please fill all required fields', 'danger')
            return redirect(url_for('register'))
        
        hashed_pw = generate_password_hash(password)
        
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, password, role, name) VALUES (?, ?, ?, ?)",
                           (email, hashed_pw, role, name))
            conn.commit()
            
            # If student, create empty profile
            if role == 'student':
                user_id = cursor.lastrowid
                cursor.execute("INSERT INTO profiles (user_id) VALUES (?)", (user_id,))
                conn.commit()
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already registered', 'danger')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['email'] = user['email']
            session['role'] = user['role']
            session['name'] = user['name']
            
            if user['role'] == 'student':
                # Check if student has skills set
                cursor.execute("SELECT skills FROM profiles WHERE user_id=?", (user['id'],))
                profile = cursor.fetchone()
                
                if profile and profile['skills']:
                    return redirect(url_for('student_dashboard'))
                else:
                    return redirect(url_for('select_skills'))
            elif user['role'] == 'company':
                return redirect(url_for('company_dashboard'))
            elif user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('home'))

# Student routes
@app.route('/student/dashboard')
def student_dashboard():
    if 'user_id' not in session or session['role'] != 'student':
        flash('Please log in as a student', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get student profile
    cursor.execute("SELECT * FROM profiles WHERE user_id=?", (session['user_id'],))
    profile = cursor.fetchone()
    
    # Redirect to skill selection if no skills set
    if not profile or not profile['skills']:
        return redirect(url_for('select_skills'))
    
    # Get applications
    cursor.execute('''
        SELECT internships.title, applications.status, applications.applied_at 
        FROM applications 
        JOIN internships ON applications.internship_id = internships.id 
        WHERE student_id=?
    ''', (session['user_id'],))
    applications = cursor.fetchall()
    
    # Get recommended internships
    recommendations = get_recommendations(session['user_id'])
    
    # Get messages
    cursor.execute('''
        SELECT messages.content, messages.sent_at, users.name as sender_name, internships.title
        FROM messages
        JOIN users ON messages.sender_id = users.id
        JOIN internships ON messages.internship_id = internships.id
        WHERE messages.receiver_id=?
    ''', (session['user_id'],))
    messages = cursor.fetchall()
    
    return render_template('student_dashboard.html', profile=profile, applications=applications, 
                           recommendations=recommendations, messages=messages)

@app.route('/student/skills', methods=['GET', 'POST'])
def select_skills():
    if 'user_id' not in session or session['role'] != 'student':
        flash('Please log in as a student', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get popular skills for suggestions
    cursor.execute("""
        SELECT skill, COUNT(*) as count 
        FROM (
            SELECT TRIM(value) as skill 
            FROM internships, json_each('["' || REPLACE(required_skills, ',', '","') || '"]')
        )
        GROUP BY skill 
        ORDER BY count DESC 
        LIMIT 20
    """)
    popular_skills = [row['skill'] for row in cursor.fetchall()]
    
    if request.method == 'POST':
        selected_skills = request.form.getlist('skills')
        additional_skills = request.form['additional_skills'].strip()
        
        if not selected_skills and not additional_skills:
            flash('Please select at least one skill', 'danger')
            return redirect(url_for('select_skills'))
        
        # Combine selected and additional skills
        all_skills = selected_skills
        if additional_skills:
            all_skills += [skill.strip() for skill in additional_skills.split(',')]
        
        skills_str = ', '.join(all_skills)
        
        try:
            cursor.execute("UPDATE profiles SET skills=? WHERE user_id=?", 
                           (skills_str, session['user_id']))
            conn.commit()
            flash('Skills updated successfully!', 'success')
            return redirect(url_for('student_dashboard'))
        except Exception as e:
            flash(f'Error updating skills: {str(e)}', 'danger')
    
    # Get user's current skills if any
    cursor.execute("SELECT skills FROM profiles WHERE user_id=?", (session['user_id'],))
    current_skills = []
    profile = cursor.fetchone()
    if profile and profile['skills']:
        current_skills = [skill.strip() for skill in profile['skills'].split(',')]
    
    return render_template('select_skills.html', 
                           popular_skills=popular_skills, 
                           current_skills=current_skills)

@app.route('/student/profile', methods=['GET', 'POST'])
def student_profile():
    if 'user_id' not in session or session['role'] != 'student':
        flash('Please log in as a student', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        skills = request.form['skills']
        education = request.form['education']
        experience = request.form['experience']
        
        try:
            cursor.execute("UPDATE profiles SET skills=?, education=?, experience=? WHERE user_id=?", 
                           (skills, education, experience, session['user_id']))
            conn.commit()
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            flash(f'Error updating profile: {str(e)}', 'danger')
        
        return redirect(url_for('student_profile'))
    
    cursor.execute("SELECT * FROM profiles WHERE user_id=?", (session['user_id'],))
    profile = cursor.fetchone()
    return render_template('student_profile.html', profile=profile)

@app.route('/internships')
def internships():
    conn = get_db()
    cursor = conn.cursor()
    
    search = request.args.get('search', '')
    if search:
        cursor.execute("SELECT * FROM internships WHERE title LIKE ? OR description LIKE ?", 
                       (f'%{search}%', f'%{search}%'))
    else:
        cursor.execute("SELECT * FROM internships")
    
    internships = cursor.fetchall()
    
    # Check if user has applied to each internship
    applied_internships = []
    if 'user_id' in session and session['role'] == 'student':
        cursor.execute("SELECT internship_id FROM applications WHERE student_id=?", (session['user_id'],))
        applied_internships = [row['internship_id'] for row in cursor.fetchall()]
    
    return render_template('internships.html', internships=internships, 
                           applied_internships=applied_internships, search=search)

@app.route('/apply/<int:internship_id>', methods=['POST'])
def apply_internship(internship_id):
    if 'user_id' not in session or session['role'] != 'student':
        flash('Please log in as a student', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if already applied
    cursor.execute("SELECT * FROM applications WHERE student_id=? AND internship_id=?", 
                   (session['user_id'], internship_id))
    if cursor.fetchone():
        flash('You have already applied to this internship', 'warning')
        return redirect(url_for('internships'))
    
    try:
        cursor.execute("INSERT INTO applications (student_id, internship_id) VALUES (?, ?)", 
                       (session['user_id'], internship_id))
        conn.commit()
        flash('Application submitted successfully!', 'success')
    except Exception as e:
        flash(f'Error applying: {str(e)}', 'danger')
    
    return redirect(url_for('internships'))

# Company routes
@app.route('/company/dashboard')
def company_dashboard():
    if 'user_id' not in session or session['role'] != 'company':
        flash('Please log in as a company', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get company's internships
    cursor.execute("SELECT * FROM internships WHERE company_id=?", (session['user_id'],))
    internships = cursor.fetchall()
    
    # Get applications for each internship
    applications = {}
    for internship in internships:
        cursor.execute('''
            SELECT applications.*, users.name as student_name 
            FROM applications 
            JOIN users ON applications.student_id = users.id 
            WHERE internship_id=?
        ''', (internship['id'],))
        applications[internship['id']] = cursor.fetchall()
    
    # Get messages
    cursor.execute('''
        SELECT messages.content, messages.sent_at, users.name as receiver_name, internships.title
        FROM messages
        JOIN users ON messages.receiver_id = users.id
        JOIN internships ON messages.internship_id = internships.id
        WHERE messages.sender_id=?
    ''', (session['user_id'],))
    messages = cursor.fetchall()
    
    return render_template('company_dashboard.html', internships=internships, 
                           applications=applications, messages=messages)

@app.route('/company/internship/post', methods=['GET', 'POST'])
def post_internship():
    if 'user_id' not in session or session['role'] != 'company':
        flash('Please log in as a company', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        required_skills = request.form['required_skills']
        
        if not title:
            flash('Title is required', 'danger')
            return redirect(url_for('post_internship'))
        
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO internships (company_id, title, description, required_skills) VALUES (?, ?, ?, ?)",
                           (session['user_id'], title, description, required_skills))
            conn.commit()
            flash('Internship posted successfully!', 'success')
            return redirect(url_for('company_dashboard'))
        except Exception as e:
            flash(f'Error posting internship: {str(e)}', 'danger')
    
    return render_template('post_internship.html')

@app.route('/application/<int:application_id>/update', methods=['POST'])
def update_application(application_id):
    if 'user_id' not in session or session['role'] != 'company':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    status = request.form['status']
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Verify the application belongs to the company
    cursor.execute('''
        SELECT internships.company_id 
        FROM applications 
        JOIN internships ON applications.internship_id = internships.id 
        WHERE applications.id=?
    ''', (application_id,))
    app_data = cursor.fetchone()
    
    if not app_data or app_data['company_id'] != session['user_id']:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        cursor.execute("UPDATE applications SET status=? WHERE id=?", (status, application_id))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/message/send', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    receiver_id = request.form['receiver_id']
    internship_id = request.form['internship_id']
    content = request.form['content']
    
    if not content:
        return jsonify({'success': False, 'message': 'Message content is required'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("INSERT INTO messages (sender_id, receiver_id, internship_id, content) VALUES (?, ?, ?, ?)",
                       (session['user_id'], receiver_id, internship_id, content))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# Admin routes
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Please log in as an admin', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get all users
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    
    # Get all internships
    cursor.execute("SELECT * FROM internships")
    internships = cursor.fetchall()
    
    # Get system stats
    cursor.execute("SELECT COUNT(*) as total_users FROM users")
    total_users = cursor.fetchone()['total_users']
    
    cursor.execute("SELECT COUNT(*) as total_internships FROM internships")
    total_internships = cursor.fetchone()['total_internships']
    
    cursor.execute("SELECT COUNT(*) as total_applications FROM applications")
    total_applications = cursor.fetchone()['total_applications']
    
    return render_template('admin_dashboard.html', users=users, internships=internships, 
                           total_users=total_users, total_internships=total_internships, 
                           total_applications=total_applications)

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Delete user and related data
        cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
        
        # Also delete related profile, applications, messages
        cursor.execute("DELETE FROM profiles WHERE user_id=?", (user_id,))
        cursor.execute("DELETE FROM applications WHERE student_id=?", (user_id,))
        cursor.execute("DELETE FROM messages WHERE sender_id=? OR receiver_id=?", (user_id, user_id))
        
        # If company, delete their internships
        cursor.execute("DELETE FROM internships WHERE company_id=?", (user_id,))
        
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/internship/<int:internship_id>/delete', methods=['POST'])
def delete_internship(internship_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Delete internship and related applications/messages
        cursor.execute("DELETE FROM internships WHERE id=?", (internship_id,))
        cursor.execute("DELETE FROM applications WHERE internship_id=?", (internship_id,))
        cursor.execute("DELETE FROM messages WHERE internship_id=?", (internship_id,))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# Recommendation algorithms
def get_recommendations(user_id):
    conn = get_db()
    cursor = conn.cursor()
    
    # Content-based recommendations
    content_recs = content_based_recommendations(user_id, cursor)
    
    # Collaborative filtering recommendations
    collab_recs = collaborative_filtering(user_id, cursor)
    
    # Combine and deduplicate recommendations
    all_recs = {rec['id']: rec for rec in content_recs}
    for rec in collab_recs:
        if rec['id'] not in all_recs:
            all_recs[rec['id']] = rec
    
    return list(all_recs.values())

def content_based_recommendations(user_id, cursor):
    # Get student's skills
    cursor.execute("SELECT skills FROM profiles WHERE user_id=?", (user_id,))
    profile = cursor.fetchone()
    
    if not profile or not profile['skills']:
        return []
    
    student_skills = set(skill.strip().lower() for skill in profile['skills'].split(','))
    
    # Get all internships
    cursor.execute("SELECT * FROM internships")
    internships = cursor.fetchall()
    
    # Calculate similarity for each internship
    recommendations = []
    for internship in internships:
        required_skills = set(skill.strip().lower() for skill in internship['required_skills'].split(',')) if internship['required_skills'] else set()
        
        if not required_skills:
            continue
            
        # Jaccard similarity
        intersection = len(student_skills & required_skills)
        union = len(student_skills | required_skills)
        similarity = intersection / union if union > 0 else 0
        
        if similarity > 0.2:  # Threshold
            recommendations.append({
                'id': internship['id'],
                'title': internship['title'],
                'similarity': similarity,
                'type': 'Content-based'
            })
    
    # Sort by similarity
    recommendations.sort(key=lambda x: x['similarity'], reverse=True)
    return recommendations[:5]  # Top 5

def collaborative_filtering(user_id, cursor):
    # Get applications of similar students
    # Step 1: Find students with similar applications
    cursor.execute("SELECT student_id, internship_id FROM applications")
    all_applications = cursor.fetchall()
    
    # Build user-item matrix
    user_items = {}
    for app in all_applications:
        student_id = app['student_id']
        internship_id = app['internship_id']
        if student_id not in user_items:
            user_items[student_id] = set()
        user_items[student_id].add(internship_id)
    
    # Find similar students based on Jaccard similarity
    current_user_apps = user_items.get(user_id, set())
    similar_students = []
    
    for student_id, apps in user_items.items():
        if student_id == user_id:
            continue
            
        intersection = len(current_user_apps & apps)
        union = len(current_user_apps | apps)
        similarity = intersection / union if union > 0 else 0
        
        if similarity > 0:
            similar_students.append((student_id, similarity))
    
    # Sort by similarity
    similar_students.sort(key=lambda x: x[1], reverse=True)
    
    # Get top internships from similar students
    recommendations = []
    seen_internships = set(current_user_apps)  # Exclude internships already applied to
    
    for student_id, similarity in similar_students[:3]:  # Top 3 similar students
        for internship_id in user_items[student_id]:
            if internship_id not in seen_internships:
                cursor.execute("SELECT * FROM internships WHERE id=?", (internship_id,))
                internship = cursor.fetchone()
                if internship:
                    recommendations.append({
                        'id': internship['id'],
                        'title': internship['title'],
                        'similarity': similarity,
                        'type': 'Collaborative'
                    })
                    seen_internships.add(internship_id)
    
    return recommendations[:5]  # Top 5

if __name__ == '__main__':
    init_db()
    app.run(debug=True)