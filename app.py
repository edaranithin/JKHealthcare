from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, send
from flask.cli import with_appcontext
import click


app = Flask(__name__)
app.secret_key = '123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jkl_healthcare.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# SocketIO setup for real-time notifications
socketio = SocketIO(app)

# Database Models

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'patient', 'caregiver', 'admin'
    address = db.Column(db.String(255), nullable=True)
    mobile = db.Column(db.String(20), nullable=True)
    medical_records = db.Column(db.Text, nullable=True)  # Only for patients
    

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    caregiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'))  
    schedule_date = db.Column(db.String(100))
    notes = db.Column(db.String(255))  # Add this line if the notes attribute is not defined

    caregiver = db.relationship('User', foreign_keys=[caregiver_id])  
    patient = db.relationship('User', foreign_keys=[patient_id]) 



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create a command line interface to set up the admin user
@click.command(name='create-admin')
@with_appcontext
def create_admin():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
        admin = User(username='admin', password=admin_password, name='Admin', role='admin')
        db.session.add(admin)
        db.session.commit()
        print("Admin user created.")
    else:
        print("Admin user already exists.")

# Register the command with Flask CLI
app.cli.add_command(create_admin)
# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

# Admin Section: Admin Dashboard for managing patients and caregivers
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    
    patients = User.query.filter_by(role='patient').all()
    caregivers = User.query.filter_by(role='caregiver').all()
    return render_template('admin_dashboard.html', patients=patients, caregivers=caregivers)

@app.route('/add_patient', methods=['GET', 'POST'])
@login_required
def add_patient():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        name = request.form['name']
        address = request.form['address']
        mobile = request.form['mobile']
        patient = User(username=username, password=password, name=name, role='patient', address=address, mobile=mobile)
        db.session.add(patient)
        db.session.commit()
        flash('Patient added successfully!')
        return redirect(url_for('admin_dashboard'))
    return render_template('add_patient.html')

@app.route('/edit_patient/<int:patient_id>', methods=['GET', 'POST'])
@login_required
def edit_patient(patient_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    
    patient = User.query.get_or_404(patient_id)
    if request.method == 'POST':
        patient.username = request.form['username']
        patient.name = request.form['name']
        patient.address = request.form['address']
        patient.mobile = request.form['mobile']
        db.session.commit()
        flash('Patient information updated successfully!')
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_patient.html', patient=patient)

@app.route('/delete_patient/<int:patient_id>', methods=['GET', 'POST'])
@login_required
def delete_patient(patient_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    
    patient = User.query.get_or_404(patient_id)
    db.session.delete(patient)
    db.session.commit()
    flash('Patient deleted successfully!')
    return redirect(url_for('admin_dashboard'))

@app.route('/assign_caregiver/<int:patient_id>', methods=['GET', 'POST'])
@login_required
def assign_caregiver(patient_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    
    patient = User.query.get_or_404(patient_id)
    caregivers = User.query.filter_by(role='caregiver').all()
    
    if request.method == 'POST':
        caregiver_id = request.form['caregiver']
        caregiver = User.query.get_or_404(caregiver_id)
        
        # Check if caregiver is already assigned
        existing_appointment = Appointment.query.filter_by(patient_id=patient.id, caregiver_id=caregiver.id).first()
        if existing_appointment:
            flash('Caregiver is already assigned to this patient!')
        else:
            appointment = Appointment(caregiver_id=caregiver.id, patient_id=patient.id, schedule_date=request.form['schedule_date'])
            db.session.add(appointment)
            db.session.commit()

            # Real-time notification to Admin and Patient
            socketio.emit('schedule_change', {'message': f'New appointment scheduled for patient {patient.name}'}, room='admin')
            socketio.emit('schedule_change', {'message': f'You have a new appointment scheduled, {patient.name}'}, room=f'patient_{patient.id}')

            flash('Caregiver assigned successfully!')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('assign_caregiver.html', patient=patient, caregivers=caregivers)

# Caregiver Section: Caregiver Dashboard and Profile
@app.route('/register_caregiver', methods=['GET', 'POST'])
def register_caregiver():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        name = request.form['name']
        address = request.form['address']
        mobile = request.form['mobile']
        caregiver = User(username=username, password=password, name=name, role='caregiver', address=address, mobile=mobile)
        db.session.add(caregiver)
        db.session.commit()
        flash('Caregiver registered successfully. Please log in.')
        return redirect(url_for('login'))
    return render_template('register_caregiver.html')

@app.route('/caregiver_dashboard')
@login_required
def caregiver_dashboard():
    if current_user.role != 'caregiver':
        return redirect(url_for('login'))
    
    # Fetch all appointments where the current caregiver is assigned
    appointments = Appointment.query.filter_by(caregiver_id=current_user.id).all()
    
    # Get the patients assigned to the caregiver through the appointments
    assigned_patients = [User.query.get(appointment.patient_id) for appointment in appointments]
    
    return render_template('caregiver_dashboard.html', appointments=appointments, assigned_patients=assigned_patients)


@app.route('/edit_caregiver_profile', methods=['GET', 'POST'])
@login_required
def edit_caregiver_profile():
    if current_user.role != 'caregiver':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_user.name = request.form['name']
        current_user.address = request.form['address']
        current_user.mobile = request.form['mobile']
        db.session.commit()
        flash('Profile updated successfully.')
        return redirect(url_for('caregiver_dashboard'))
    return render_template('edit_caregiver_profile.html', caregiver=current_user)

@app.route('/update_appointment/<int:appointment_id>', methods=['GET', 'POST'])
@login_required
def update_appointment(appointment_id):
    # Fetch the appointment and make sure it includes the related patient
    appointment = Appointment.query.get_or_404(appointment_id)
    
    if request.method == 'POST':
        # Update the appointment details here (e.g., schedule_date)
        appointment.schedule_date = request.form['schedule_date']
        db.session.commit()
        
        # Emit notifications
        socketio.emit('schedule_change', {'message': f'Appointment for patient {appointment.patient.name} has been updated.'}, room='admin')
        socketio.emit('schedule_change', {'message': f'Your appointment has been updated, {appointment.patient.name}'}, room=f'patient_{appointment.patient.id}')
        
        flash('Appointment updated successfully.')
        return redirect(url_for('caregiver_dashboard'))
    
    return render_template('update_appointment.html', appointment=appointment)


@app.route('/remove_caregiver/<int:appointment_id>', methods=['GET', 'POST'])
@login_required
def remove_caregiver(appointment_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Remove the caregiver's assignment by deleting the appointment
    db.session.delete(appointment)
    db.session.commit()
    
    # Emit notifications to admin and patient about the caregiver removal
    socketio.emit('schedule_change', {'message': f'Caregiver removed from patient {appointment.patient.name}'}, room='admin')
    socketio.emit('schedule_change', {'message': f'Your caregiver has been removed, {appointment.patient.name}'}, room=f'patient_{appointment.patient.id}')
    
    flash('Caregiver removed successfully!')
    return redirect(url_for('admin_dashboard'))


# Patient Section: Patient Dashboard and Profile
@app.route('/patient_dashboard')
@login_required
def patient_dashboard():
    if current_user.role != 'patient':
        return redirect(url_for('login'))
    
    return render_template('patient_dashboard.html', patient=current_user)

@app.route('/edit_patient_profile', methods=['GET', 'POST'])
@login_required
def edit_patient_profile():
    if current_user.role != 'patient':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_user.username = request.form['username']
        current_user.name = request.form['name']
        current_user.address = request.form['address']
        current_user.mobile = request.form['mobile']
        db.session.commit()
        flash('Profile updated successfully.')
        return redirect(url_for('patient_dashboard'))
    return render_template('edit_patient_profile.html', patient=current_user)

# Authentication Routes: Login and Logout
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'caregiver':
                return redirect(url_for('caregiver_dashboard'))
            elif user.role == 'patient':
                return redirect(url_for('patient_dashboard'))
        else:
            flash('Login Failed. Please check your credentials.')
    return render_template('login.html')

@app.route('/register_patient', methods=['GET', 'POST'])
def register_patient():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        name = request.form['name']
        address = request.form['address']
        mobile = request.form['mobile']
        
        # Create a new patient
        patient = User(username=username, password=password, name=name, role='patient', address=address, mobile=mobile)
        db.session.add(patient)
        db.session.commit()
        
        flash('Patient registered successfully. Please log in.')
        return redirect(url_for('login'))  # Redirect to login page after registration
    return render_template('register_patient.html')  # You will need to create this template

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Real-time Notification Handler
@socketio.on('connect')
def handle_connect():
    if current_user.role == 'admin':
        socketio.emit('schedule_change', {'message': 'Admin connected to the system.'}, room='admin')
    elif current_user.role == 'patient':
        socketio.emit('schedule_change', {'message': f'Patient {current_user.name} connected to the system.'}, room=f'patient_{current_user.id}')

if __name__ == "__main__":
    socketio.run(app, debug=True)
