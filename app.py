from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///streetsaver.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'

db = SQLAlchemy(app)

# ===================== MODELS =====================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(120))
    contact = db.Column(db.String(20))
    place = db.Column(db.String(120))
    profile_pic = db.Column(db.String(200))  # filename of uploaded profile picture

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100))
    description = db.Column(db.Text)
    location = db.Column(db.String(200))
    contact = db.Column(db.String(20))
    date = db.Column(db.String(50))
    image = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_name = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    place = db.Column(db.String(120))
    contact = db.Column(db.String(20))
    address = db.Column(db.String(200))
    pincode = db.Column(db.String(20))
    proof_file = db.Column(db.String(200))  # filename of uploaded proof
    proof_status = db.Column(db.String(50), default='Pending')  # Pending, Approved, Rejected

# ===================== ROUTES =====================

@app.route('/')
def index():
    if 'user_id' in session:
        all_reports = Report.query.order_by(Report.id.desc()).all()
        my_reports = Report.query.filter_by(user_id=session['user_id']).order_by(Report.id.desc()).all()
        user = User.query.get(session['user_id'])
        users = User.query.all()
        user_map = {u.id: u for u in users}
        return render_template(
            'home.html',
            all_reports=all_reports,
            my_reports=my_reports,
            logged_in=True,
            username=user.username,
            full_name=user.full_name or '',
            contact=user.contact or '',
            place=user.place or '',
            profile_pic=user.profile_pic,
            user_map=user_map
        )
    return redirect(url_for('login'))

ADMIN_USERNAME = "adminuser"
ADMIN_PASSWORD = "adminpass"

@app.route('/admin')
def admin_module():
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))
    all_reports = Report.query.order_by(Report.id.desc()).all()
    users = User.query.all()
    user_map = {u.id: u for u in users}
    return render_template('admin.html', message="This is admin module", all_reports=all_reports, user_map=user_map)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_module'))
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash("Login successful!", "success")
            return redirect(url_for('index'))
        org = Organization.query.filter_by(username=username).first()
        if org and check_password_hash(org.password, password):
            session['org_id'] = org.id
            flash('Organization login successful!', 'success')
            return redirect(url_for('org_verification'))
        flash("Invalid credentials", "danger")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(username=request.form['username']).first():
            flash("Username already exists", "danger")
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(request.form['password'])
        new_user = User(
            username=request.form['username'],
            password=hashed_pw,
            full_name=request.form.get('full_name', ''),
            contact=request.form.get('contact', ''),
            place=request.form.get('place', '')
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Registered successfully! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route('/submit', methods=['GET', 'POST'])
def submit():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['image']
        filename = None
        if file and file.filename != '':
            filename = datetime.now().strftime("%Y%m%d%H%M%S_") + file.filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        report = Report(
            category=request.form['category'],
            description=request.form['description'],
            location=request.form['location'],
            contact=request.form['contact'],
            date=request.form['date'],
            image=filename,
            user_id=session['user_id']
        )
        db.session.add(report)
        db.session.commit()
        flash("Report submitted successfully!", "success")
        return redirect(url_for('index'))

    return render_template('submit.html')

@app.route('/delete/<int:id>', methods=['POST'])
def delete(id):
    # Admin delete logic
    if request.form.get('admin') == '1':
        report = Report.query.get_or_404(id)
        db.session.delete(report)
        db.session.commit()
        flash("Report deleted by admin.", "info")
        return redirect(url_for('admin_module'))
    # User delete logic
    if 'user_id' not in session:
        return redirect(url_for('login'))

    report = Report.query.get_or_404(id)
    if report.user_id == session['user_id']:
        db.session.delete(report)
        db.session.commit()
        flash("Report deleted successfully.", "info")
    else:
        flash("Unauthorized delete attempt.", "danger")
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template(
        'profile.html',
        username=user.username,
        full_name=user.full_name or '',
        contact=user.contact or '',
        place=user.place or '',
        profile_pic=user.profile_pic
    )

# Route to update profile picture
@app.route('/update_profile_pic', methods=['POST'])
def update_profile_pic():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    file = request.files.get('profile_pic')
    if file and file.filename != '':
        filename = datetime.now().strftime("%Y%m%d%H%M%S_") + file.filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        user.profile_pic = filename
        db.session.commit()
        flash("Profile picture updated!", "success")
    else:
        flash("No image selected.", "warning")
    return redirect(url_for('profile'))

@app.route('/view_all_users')
def view_all_users():
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))
    users = User.query.all()
    return render_template('admin.html', all_users=users, show_users=True)

@app.route('/admin/user/<int:user_id>')
def admin_user_profile(user_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))
    user = User.query.get_or_404(user_id)
    user_reports = Report.query.filter_by(user_id=user_id).order_by(Report.id.desc()).all()
    return render_template('admin.html', admin_user=user, show_admin_user_profile=True, user_reports=user_reports)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))
    user = User.query.get_or_404(user_id)
    # Delete all reports by this user
    Report.query.filter_by(user_id=user_id).delete()
    db.session.delete(user)
    db.session.commit()
    flash('User and all their reports have been removed.', 'info')
    return redirect(url_for('view_all_users'))

@app.route('/org_register', methods=['GET', 'POST'])
def org_register():
    if request.method == 'POST':
        org_name = request.form['org_name']
        username = request.form['username']
        password = request.form['password']
        re_password = request.form['re_password']
        place = request.form['place']
        contact = request.form['contact']
        address = request.form['address']
        pincode = request.form['pincode']
        if password != re_password:
            flash('Passwords do not match.', 'danger')
            return render_template('org_register.html')
        if Organization.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('org_register.html')
        if Organization.query.filter_by(org_name=org_name).first():
            flash('Organization name already exists.', 'danger')
            return render_template('org_register.html')
        hashed_pw = generate_password_hash(password)
        new_org = Organization(
            org_name=org_name,
            username=username,
            password=hashed_pw,
            place=place,
            contact=contact,
            address=address,
            pincode=pincode
        )
        db.session.add(new_org)
        db.session.commit()
        flash('Organization registered successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('org_register.html')

@app.route('/org_verification', methods=['GET', 'POST'])
def org_verification():
    if 'org_id' not in session:
        return redirect(url_for('login'))
    org = Organization.query.get(session['org_id'])
    proof_file = org.proof_file if org.proof_file else None
    proof_status = org.proof_status
    if request.method == 'POST':
        # Only allow submission if no proof has been submitted yet
        if not org.proof_file:
            file = request.files.get('proof_file')
            if file and file.filename != '':
                filename = datetime.now().strftime("%Y%m%d%H%M%S_") + file.filename
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                org.proof_file = filename
                org.proof_status = 'Pending'
                db.session.commit()
                flash('Proof has been sent for review. Pending review.', 'info')
                session['org_proof_file'] = filename
                proof_file = filename
                proof_status = 'Pending'
            else:
                flash('Please select a file to upload.', 'danger')
        else:
            flash('Proof already submitted. Only one submission allowed.', 'warning')
    return render_template('org_verification.html', proof_sent=bool(proof_file), proof_file=proof_file, proof_status=proof_status)

@app.route('/delete_all_orgs', methods=['POST'])
def delete_all_orgs():
    Organization.query.delete()
    db.session.commit()
    flash('All organizations deleted.', 'info')
    return redirect(url_for('org_register'))

@app.route('/verify_logins')
def verify_logins():
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))
    return '<h2 style="text-align:center; margin-top:100px;">verify logins</h2>'

# ===================== DB INIT =====================

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
