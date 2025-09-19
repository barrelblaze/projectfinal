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
    status = db.Column(db.String(50), default='Pending')
    updated_by_org_id = db.Column(db.Integer, db.ForeignKey('organization.id'))

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
    profile_pic = db.Column(db.String(200))  # filename of uploaded organization profile picture

# ===================== ROUTES =====================

@app.route('/')
def index():
    if 'user_id' in session:
        all_reports = Report.query.order_by(Report.id.desc()).all()
        my_reports = Report.query.filter_by(user_id=session['user_id']).order_by(Report.id.desc()).all()
        user = User.query.get(session['user_id'])
        users = User.query.all()
        user_map = {u.id: u for u in users}
        orgs = Organization.query.all()
        org_map = {o.id: o for o in orgs}
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
            user_map=user_map,
            org_map=org_map
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
            if org.proof_status == 'Approved':
                return redirect(url_for('org_home'))
            else:
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
    if proof_status == 'Approved':
        session.pop('org_id', None)
        return redirect(url_for('login'))
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
    orgs = Organization.query.all()
    # Render admin.html with a flag to show the verify logins section and pass orgs
    return render_template('admin.html', show_verify_logins=True, orgs=orgs)

@app.route('/view_all_orgs')
def view_all_orgs():
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))
    orgs = Organization.query.all()
    return render_template('admin.html', show_all_orgs=True, orgs=orgs)

@app.route('/admin/delete_org/<int:org_id>', methods=['POST'])
def admin_delete_org(org_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))
    org = Organization.query.get_or_404(org_id)
    db.session.delete(org)
    db.session.commit()
    flash('Organization and all its data have been removed.', 'info')
    return redirect(url_for('view_all_orgs'))

@app.route('/admin/verify_org/<int:org_id>', methods=['POST'])
def admin_verify_org(org_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))
    org = Organization.query.get_or_404(org_id)
    action = request.form.get('action')
    if action == 'approve':
        org.proof_status = 'Approved'
        flash('Organization proof approved.', 'success')
    elif action == 'reject':
        org.proof_status = 'Rejected'
        flash('Organization proof rejected.', 'danger')
    db.session.commit()
    return redirect(url_for('verify_logins'))

@app.route('/org_home')
def org_home():
    if 'org_id' not in session:
        return redirect(url_for('login'))
    all_reports = Report.query.order_by(Report.id.desc()).all()
    users = User.query.all()
    user_map = {u.id: u for u in users}
    return render_template('org_home.html', all_reports=all_reports, user_map=user_map)

@app.route('/org_profile')
def org_profile():
    if 'org_id' not in session:
        return redirect(url_for('login'))
    org = Organization.query.get(session['org_id'])
    return render_template(
        'org_profile.html',
        org_name=org.org_name,
        username=org.username,
        place=org.place,
        contact=org.contact,
        address=org.address,
        pincode=org.pincode,
        proof_file=org.proof_file,
        proof_status=org.proof_status,
        profile_pic=org.profile_pic
    )

@app.route('/org_update_profile_pic', methods=['POST'])
def org_update_profile_pic():
    if 'org_id' not in session:
        return redirect(url_for('login'))
    org = Organization.query.get(session['org_id'])
    file = request.files.get('profile_pic')
    if file and file.filename != '':
        filename = datetime.now().strftime("%Y%m%d%H%M%S_") + file.filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        org.profile_pic = filename
        db.session.commit()
        flash('Profile picture updated!', 'success')
    else:
        flash('No image selected.', 'warning')
    return redirect(url_for('org_profile'))

@app.route('/org/report/<int:report_id>/status', methods=['POST'])
def org_update_report_status(report_id):
    if 'org_id' not in session:
        return redirect(url_for('login'))
    new_status = request.form.get('status')
    if new_status not in ['Pending', 'Acknowledged', 'Solved']:
        flash('Invalid status update.', 'danger')
        return redirect(url_for('org_home'))
    report = Report.query.get_or_404(report_id)
    report.status = new_status
    report.updated_by_org_id = session['org_id']
    db.session.commit()
    flash(f'Report status updated to {new_status}.', 'org_status')
    return redirect(url_for('org_home'))

# ===================== DB INIT =====================

with app.app_context():
    db.create_all()
    # Lightweight SQLite migration: ensure 'status' column exists on 'report'
    try:
        from sqlalchemy import text
        result = db.session.execute(text("PRAGMA table_info(report)"))
        columns = [row[1] for row in result]
        if 'status' not in columns:
            db.session.execute(text("ALTER TABLE report ADD COLUMN status VARCHAR(50) DEFAULT 'Pending'"))
            db.session.commit()
    except Exception:
        # Avoid breaking app if migration check fails
        pass
    # Ensure 'profile_pic' column exists on 'organization'
    try:
        from sqlalchemy import text
        result = db.session.execute(text("PRAGMA table_info(organization)"))
        columns = [row[1] for row in result]
        if 'profile_pic' not in columns:
            db.session.execute(text("ALTER TABLE organization ADD COLUMN profile_pic VARCHAR(200)"))
            db.session.commit()
    except Exception:
        pass
    # Ensure 'updated_by_org_id' column exists on 'report'
    try:
        from sqlalchemy import text
        result = db.session.execute(text("PRAGMA table_info(report)"))
        columns = [row[1] for row in result]
        if 'updated_by_org_id' not in columns:
            db.session.execute(text("ALTER TABLE report ADD COLUMN updated_by_org_id INTEGER"))
            db.session.commit()
    except Exception:
        pass
    # Backfill attribution for already updated reports (Acknowledged/Solved) with no org recorded
    try:
        any_org = Organization.query.order_by(Organization.id.asc()).first()
        if any_org is not None:
            missing = Report.query.filter(
                Report.status.in_(['Acknowledged', 'Solved']),
                (Report.updated_by_org_id.is_(None))
            ).all()
            for r in missing:
                r.updated_by_org_id = any_org.id
            if missing:
                db.session.commit()
    except Exception:
        pass

if __name__ == '__main__':
    app.run(debug=True)
