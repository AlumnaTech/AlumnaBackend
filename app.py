from flask import Flask, request, jsonify, session
from flask_session import Session
from flask_migrate import Migrate
from getfilelistpy import getfilelist
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
from flask_cors import CORS
from flask import abort
from functools import wraps
from datetime import datetime, timedelta
import smtplib
import random
import jwt
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy.exc import IntegrityError
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import werkzeug
import os
import tempfile
import shutil

import upload_folder

BASEDIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

app.debug = True

CORS(app)

app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY', '7d290cca20d192a4a68d64c6')

# SESSION CONFIGURATION
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=5)
Session(app)

# DATABASE CONFIGURATION
if os.getenv('DATABASE_URL'):
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
        'DATABASE_URL').replace("postgres://", "postgresql://", 1)
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.abspath(os.path.join(BASEDIR, 'instance', 'alumna.db'))}"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# CONFIGURE LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)

# unilorin folder
Unilorin_folder = upload_folder.Unilorin_folder


# DEFINE CUSTOM FUNCTIONS

# --------Generate a verification token with user email and id--------
def generate_verification_token(user_id):
    user = User.query.get(user_id)

    if not user:
        return None

    # Token expires in 10 min
    expiration_time = datetime.utcnow() + timedelta(hours=24)
    payload = {
        "user_id": user_id,
        "email": user.email,
        "exp": expiration_time.timestamp() * 1000,
    }

    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")
    return token

# ------TO GENERATE EMAIL CODE-------


def generate_verification_code():
    # CREATE EMAIL VERIFICATION CODE
    verify_code = []
    for i in range(0, 4):
        digit = random.randint(0, 9)
        verify_code.append(digit)
    digit_code = ''.join(str(i) for i in verify_code)
    return digit_code


# ------TO SEND EMAIL-------------
def send_mail(email, name, code):
    my_email = 'alumnatech@gmail.com'
    my_password = 'lmnkpqcwtuuvyuto'

    # ------OPENS VERIFICATION EMAIL TEXT AND INPUTS USERNAME AND GENERATED CODE---------------
    with open("verifyemail.txt", "r") as mail:
        email_template = mail.read()
        email_content = email_template.format(NAME=name, CODE=code)
    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(user=my_email, password=my_password)
        connection.sendmail(from_addr=my_email, to_addrs=email,
                            msg=f"Subject:Welcome- Verify your email address.\n\n{email_content}")


# ------CONFIRMS IF CORRECT CODE WAS ENTERED-----------
def confirm_code(ans_code, code):
    if code == ans_code:
        return True
    else:
        return False


# Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If class rep is not yes then return abort with 403 error
        if current_user.class_rep.lower() != 'yes':
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    level = db.Column(db.String(20), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    faculty = db.Column(db.String(100), nullable=False)
    institution = db.Column(db.String(100), nullable=False)
    matno = db.Column(db.String(20), nullable=False)
    class_rep = db.Column(db.Boolean, nullable=False)

    # Extra Temporary fields for verification
    verified = db.Column(db.Boolean, default=False, nullable=False)
    verification_code = db.Column(db.String(4))
    verification_code_expiration = db.Column(db.DateTime)
    attempts = db.Column(db.Integer, default=3)

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "level": self.level,
            "department": self.department,
            "faculty": self.faculty,
            "institution": self.institution,
            "matno": self.matno,
            "class_rep": self.class_rep,
        }

    def get_id(self):
        return str(self.id)

    @property
    def is_authenticated(self):
        return True  # Return True if the user is authenticated

    @property
    def is_active(self):
        return self.verified

    @property
    def is_anonymous(self):
        return False  # Return False for authenticated users


class Classes(db.Model):
    __tablename__ = "classes"
    id = db.Column(db.Integer, primary_key=True)
    department = db.Column(db.String(550), nullable=False)
    level = db.Column(db.String(250), nullable=False)
    institution = db.Column(db.String(550), nullable=False)
    course_code = db.Column(db.String(50), nullable=False)
    course_title = db.Column(db.String(250), nullable=False)
    lecturer = db.Column(db.String(1000), nullable=True)
    date = db.Column(db.String(550), nullable=False)
    venue = db.Column(db.String(550), nullable=False)
    start_time = db.Column(db.String(120), nullable=True)
    stop_time = db.Column(db.String(120), nullable=True)
    desc = db.Column(db.String(2000), nullable=True)

    def serialize(self):
        return {
            'id': self.id,
            'type': 'class',
            'department': self.department,
            'level': self.level,
            'institution': self.institution,
            'course_code': self.course_code,
            'course_title': self.course_title,
            'lecturer': self.lecturer,
            'date': self.date,
            'venue': self.venue,
            'start_time': self.start_time,
            'stop_time': self.stop_time,
            'desc': self.desc,
        }


class Tests(db.Model):
    __tablename__ = "upcoming_tests"
    id = db.Column(db.Integer, primary_key=True)
    department = db.Column(db.String(550), nullable=False)
    level = db.Column(db.String(250), nullable=False)
    institution = db.Column(db.String(550), nullable=False)
    course_code = db.Column(db.String(50), nullable=False)
    course_title = db.Column(db.String(250), nullable=False)
    lecturer = db.Column(db.String(1000), nullable=True)
    date = db.Column(db.String(550), nullable=False)
    venue = db.Column(db.String(550), nullable=False)
    start_time = db.Column(db.String(120), nullable=True)
    stop_time = db.Column(db.String(120), nullable=True)
    desc = db.Column(db.String(2000), nullable=True)

    def serialize(self):
        return {
            'id': self.id,
            'type': 'test',
            'department': self.department,
            'level': self.level,
            'institution': self.institution,
            'course_code': self.course_code,
            'course_title': self.course_title,
            'lecturer': self.lecturer,
            'date': self.date,
            'venue': self.venue,
            'start_time': self.start_time,
            'stop_time': self.stop_time,
            'desc': self.desc,
        }


class Assignments(db.Model):
    __tablename__ = "upcoming_assignments"
    id = db.Column(db.Integer, primary_key=True)
    department = db.Column(db.String(550), nullable=False)
    level = db.Column(db.String(250), nullable=False)
    institution = db.Column(db.String(550), nullable=False)
    course_code = db.Column(db.String(50), nullable=False)
    course_title = db.Column(db.String(250), nullable=False)
    lecturer = db.Column(db.String(1000), nullable=True)
    date = db.Column(db.String(550), nullable=False)
    time = db.Column(db.String(120), nullable=True)
    desc = db.Column(db.String(2000), nullable=True)

    def serialize(self):
        return {
            'id': self.id,
            'type': 'assignment',
            'department': self.department,
            'level': self.level,
            'institution': self.institution,
            'course_code': self.course_code,
            'course_title': self.course_title,
            'lecturer': self.lecturer,
            'date': self.date,
            'time': self.time,
            'desc': self.desc,
        }


class Presentations(db.Model):
    __tablename__ = "upcoming_presentations"
    id = db.Column(db.Integer, primary_key=True)
    department = db.Column(db.String(550), nullable=False)
    level = db.Column(db.String(250), nullable=False)
    institution = db.Column(db.String(550), nullable=False)
    course_code = db.Column(db.String(50), nullable=False)
    course_title = db.Column(db.String(250), nullable=False)
    lecturer = db.Column(db.String(250), nullable=True)
    date = db.Column(db.String(550), nullable=False)
    venue = db.Column(db.String(550), nullable=False,)
    start_time = db.Column(db.String(120), nullable=True)
    stop_time = db.Column(db.String(120), nullable=True)
    desc = db.Column(db.String(2000), nullable=True)

    def serialize(self):
        return {
            'id': self.id,
            'type': 'presentation',
            'department': self.department,
            'level': self.level,
            'institution': self.institution,
            'course_code': self.course_code,
            'course_title': self.course_title,
            'lecturer': self.lecturer,
            'date': self.date,
            'venue': self.venue,
            'start_time': self.start_time,
            'stop_time': self.stop_time,
            'desc': self.desc,
        }


# Line below only required once, when creating DB.
with app.app_context():
    db.create_all()


# ------DASHBOARD---------------
@app.route('/dashboard', methods=['GET'])
def dashboard():
    institution = request.args.get('institution')
    department = request.args.get('department')
    level = request.args.get('level')
    todays_date = datetime.today().date()

# -------------------DELETE PAST EVENTS AND CLASSES--------------------
    # PAST CLASSES
    classes_check = Classes.query.all()
    for clas in classes_check:
        if clas.date < todays_date:
            db.session.delete(clas)
            db.session.commit()

    # PAST TESTSsession
    tests_check = Tests.query.all()
    for test in tests_check:
        if test.date < todays_date:
            db.session.delete(test)
            db.session.commit()

    # PAST ASSIGNMENTS
    assn_check = Assignments.query.all()
    for assn in assn_check:
        if assn.date < todays_date:
            db.session.delete(assn)
            db.session.commit()

    # PAST PRESENTATIONS
    pres_check = Presentations.query.all()
    for pres in pres_check:
        if pres.date < todays_date:
            db.session.delete(pres)
            db.session.commit()

    # Query Classes, Tests, Assignments, and Presentations based on filters
    classes = Classes.query.filter_by(
        institution=institution, department=department, level=level, date=todays_date).order_by(Classes.start_time).all()
    tests = Tests.query.filter_by(
        institution=institution, department=department, level=level).order_by(Tests.date).all()
    assignments = Assignments.query.filter_by(
        institution=institution, department=department, level=level).order_by(Assignments.deadline).all()
    presentations = Presentations.query.filter_by(
        institution=institution, department=department, level=level).order_by(Tests.date).all()

    events = []
    for row in presentations:
        events.append(row)
    for row in assignments:
        events.append(row)
    for row in tests:
        events.append(row)
    for i in range(len(events)):
        if events[i].date < events[0].date:
            event = events[i]
            events.pop(i)
            events.insert(0, event)

    data = {
        'classes': [cls.serialize() for cls in classes],
        'upcoming_events': [event.serialize() for event in events],
    }
    return jsonify(data), 200


# ---------DRAG AND DROP FILES FOR MATERIAL POOL----------
@app.route('/upload', methods=['POST'])
def upload_file():
    # print(request.headers.get('Content-Type'))

    # print("Form Data:", request.form)

    # print("files:", request.files.getlist("files"))

    if request.method == 'POST':
        uploaded_files = request.files.getlist("files")
        faculty = request.form['faculty']
        department = request.form['department']
        level = request.form['level']

        # Temporary directory to store the uploaded files
        temp_dir = tempfile.mkdtemp()

        if uploaded_files:
            # ----------UPLOAD TO GOOGLE DRIVE--------------
            gauth = GoogleAuth()
            gauth.LocalWebserverAuth()
            drive = GoogleDrive(gauth)
            folder_id = Unilorin_folder[faculty][department][level]

            # -------ADD FILE HERE-------
            for uploaded_file in uploaded_files:
                file_path = os.path.join(temp_dir, uploaded_file.filename)
                uploaded_file.save(file_path)

                # Upload the file to Google Drive
                file = drive.CreateFile({'parents': [{'id': folder_id}]})
                file.SetContentFile(file_path)
                file.Upload()

            # Remove the temporary directory and its contents after uploading
            shutil.rmtree(temp_dir)
            return jsonify({'message': 'File uploaded successfully'}), 201

    return jsonify({'message': 'Invalid request'}), 400


# ---------VIEW FILES IN MATERIAL POOL----------
@app.route('/view-materials', methods=['GET', 'POST'])
def view_files():
    if request.method == 'POST':
        data = request.json
        faculty = data['faculty']
        department = data['department']
        level = data['level']
        # course_code = data['course_code']

#  -------- GET MATERIALS FROM GOOGLE DRIVE -----------
        folder_id = Unilorin_folder[faculty][department][level]
        resource = {
            "api_key": "AIzaSyDRVHX6J2DXnmadLcMHkgNuqTBMf_nL3oI",
            "id": folder_id,
        }
        r = getfilelist.GetFileList(resource)
        materials = []
        for i in range(len(r['fileList'][0]['files'])):
            materials.append(r['fileList'][0]['files'][i]['webViewLink'])

        data = {
            'materials': [materials]
        }
        return jsonify(data), 200


# ------ADMIN CREATE EVENTS---------------
@app.route('/add-class', methods=['POST', 'GET'])
def add_class():
    if request.method == 'POST':
        data = request.json

        new_class = Classes(
            department=data['department'],
            level=data['level'],
            institution=data['institution'],
            course_code=data['course-code'],
            date=data['date'],
            lecturer=data['lecturer'],
            venue=data['venue'],
            start_time=data['start'],
            stop_time=data['stop'],
        )
        db.session.add(new_class)
        db.session.commit()

        return jsonify({'message': 'Class added successfully'}), 201
    return jsonify({'message': 'Invalid request'}), 400


@app.route('/add-test', methods=['POST', 'GET'])
def add_test():
    if request.method == 'POST':
        data = request.json

        new_test = Tests(
            department=data['department'],
            level=data['level'],
            institution=data['institution'],
            course_code=data['courseCode'],
            course_title="bioinformatics",
            date=data['date'],
            lecturer="lecturer",
            venue=data['venue'],
            start_time=data['startTime'],
            stop_time=data['stopTime']
        )

        db.session.add(new_test)
        db.session.commit()

        return jsonify({'message': 'Test added successfully'}), 201
    return jsonify({'message': 'Invalid request'}), 400


@app.route('/add-assignment', methods=['POST', 'GET'])
def add_assignment():
    if request.method == 'POST':
        # print("current: ", current_user.to_dict())
        data = request.json

        new_assignment = Assignments(
            department=data['department'],
            level=data['level'],
            institution=data['institution'],
            course_code=data['courseCode'],
            course_title=data['courseTitle'],
            date=data['date'],
            lecturer=data['lecturer'],

        )

        db.session.add(new_assignment)
        db.session.commit()

        return jsonify({'message': 'Assignment added successfully'}), 201
    return jsonify({'message': 'Invalid request'}), 400


@app.route('/add-presentation', methods=['POST', 'GET'])
# @admin_only
def add_presentation():
    if request.method == 'POST':
        data = request.json

        new_presentation = Presentations(
            department=data['department'],
            level=data['level'],
            institution=data['institution'],
            course_code=data['courseCode'],
            course_title=data['courseTitle'],
            date=data['date'],
            lecturer=data['lecturer'],
            venue=data['venue'],
            start_time=data['startTime'],
            stop_time=data['stopTime']
        )

        db.session.add(new_presentation)
        db.session.commit()

        return jsonify({'message': 'Presentation added successfully'}), 201

    return jsonify({'message': 'Invalid request'}), 400


# ------FOR REGISTRATION----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        try:
            # FIRST, CHECK TO SEE IF EMAIL IS ALREADY IN RECORD
            existing_user = User.query.filter_by(email=data['email']).first()

            if existing_user:
                if existing_user.verified:
                    # User already exists and is verified
                    return jsonify({"message": "Your email address has been registered and verified, please log in!",
                                    }), 409
                else:
                    db.session.delete(existing_user)
                    db.session.commit()

            # CREATE RECORD
            plaintext_password = data['password']
            new_user = User(
                name=data['fullname'],
                email=data['email'],
                password=generate_password_hash(
                    plaintext_password, method='pbkdf2:sha256', salt_length=8),
                level=data['level'],
                matno=data['matno'],
                department=data['department'],
                faculty=data['faculty'],
                institution=data['institution'],
                class_rep="yes"
            )
            db.session.add(new_user)
            db.session.commit()

            session["user_id"] = new_user.id

            return jsonify({
                "id": new_user.id,
                "email": new_user.email}), 201  # Status code 201 for successful registration

        except IntegrityError as e:
            db.session.rollback()
            print(e)
            return jsonify({"message": "An error occurred while registering. Please try again later."}), 500

        except Exception as e:
            db.session.rollback()
            print(e)
            return jsonify({"message": "An unexpected error occurred. Please try again later."}), 500


# ------TO VERIFY USER EMAIL ADDRESS----------------
@app.route('/verify/<int:user_id>', methods=['GET', 'POST', 'DELETE'])
def verify(user_id):
    requested_user = User.query.get(user_id)

    # Check if the user already has an 'attempts' attribute in the database, and initialize it if not.
    if not hasattr(requested_user, 'attempts'):
        requested_user.attempts = 3  # Initialize with 3 attempts
        db.session.commit()

    if request.method == 'GET':

        # ------GENERATE VERIFICATION TOKEN AND SENDS EMAIL ONCE--------------
        token = generate_verification_token(user_id)

        # ------GETS VERIFICATION CODE AND SETS VERIFICATION CODE TIME LIMIT---------
        code = generate_verification_code()
        code_expiration = datetime.now() + timedelta(minutes=10)
        requested_user.verification_code = code
        requested_user.verification_code_expiration = code_expiration
        db.session.commit()

        if token:
            send_mail(requested_user.email,
                      requested_user.name, code)
            return jsonify({"message": "A verification mail has been sent to your inbox", "token": token},  200)
        else:
            return jsonify({"message": "User not found"}), 404

    if request.method == 'DELETE':  # New block to handle deleting the existing code attempts
        new_code = generate_verification_code()
        send_mail(requested_user.email, requested_user.name, new_code)

        # Store the new code and its expiration time in the databse
        requested_user.verification_code = new_code
        requested_user.verification_code_expiration = datetime.now() + \
            timedelta(minutes=10)
        db.session.commit()

        return jsonify({"message": "A new verification code has been sent to your inbox."}), 200

    if request.method == 'POST':

        data = request.get_json()
        input_code = data['code']

       # Retrieve the stored code and its expiration time
        stored_code = requested_user.verification_code

        code_expiration = requested_user.verification_code_expiration

        # ------CHECKS IF TIME LIMIT IS EXCEEDED----------
        if datetime.now() and code_expiration:
            if datetime.now() > code_expiration:
                return jsonify({"message": "The verification code has expired. Please request another code."}), 400
            else:
                # ------CONFIRMS THAT CORRECT CODE WAS ENTERED---------

                if confirm_code(input_code.strip(), stored_code.strip()) == True:
                    requested_user.verified = True
                    # Delete the verification code-related fields from the user object
                    # del requested_user.verification_code
                    # del requested_user.verification_code_expiration
                    db.session.commit()
                    return jsonify({"message": "You can now login to your account."}, 200)

                else:
                    requested_user.attempts -= 1  # Decrement the attempts count
                    db.session.commit()

                    if requested_user.attempts > 0:
                        if requested_user.attempts == 1:
                            trials = "1 trial"
                        else:
                            trials = f"{requested_user.attempts} trials"
                        return jsonify({"message": f"You have entered an incorrect code. You have {trials} left"}, 400)
                    else:
                        db.session.delete(requested_user)
                        db.session.commit()
                        return jsonify({"message": "Verification failed. Your account has been deleted."}), 401
        else:
            print("no time")

    # Check if the token has expired
    token = request.args.get('token')
    try:
        payload = jwt.decode(
            token, app.config["SECRET_KEY"], algorithms=["HS256"])
        if datetime.now() > datetime.fromtimestamp(payload['exp']):
            db.session.delete(requested_user)
            db.session.commit()
            return jsonify({"message": "Verification failed. Your account has been deleted."}), 401
    except jwt.ExpiredSignatureError:
        db.session.delete(requested_user)
        db.session.commit()
        return jsonify({"message": "Verification failed. Your account has been deleted."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid verification token"}), 400


# ------FOR LOGIN IN----------------
@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        email = data['email']
        password = data['password']
        # Find user by email entered.
        user = User.query.filter_by(email=email).first()

        if not user:
            return jsonify({"message": "This email has not been registered. Please register."}), 404

        # Check stored password hash against entered password hash.
        if check_password_hash(user.password, password):
            if user.verified:
                login_user(user)
                logged_in = current_user.is_authenticated
                active_user = user.to_dict()
                payload = {'user': active_user, 'logged_in': True}
                token = jwt.encode(
                    payload, app.config["SECRET_KEY"], algorithm="HS256")

                return jsonify({"message": "Login successful", 'token': token}), 200
            else:
                return jsonify({"message": "Your email is not yet verified. Please verify your email to proceed."}), 401
        else:
            return jsonify({"message": "Password incorrect. Please try again."}), 401

    # if request.method == 'GET':
    #     print(current_user)
    #     if current_user.is_authenticated:

    #         # User is logged in

    #         return jsonify({"message": "User is logged in", "logged_in": True, "user": current_user}), 200
    #     else:
    #         # User is not logged in
    #         return jsonify({"message": "User is not logged in", "logged_in": False}), 401

    # return jsonify({"message": "Method not allowed"}), 405


# ------LOGS USER OUT----------


@app.route('/logout')
def logout():
    logout_user()
    # return redirect(url_for('home'))


# ---------DELETES USER ACCOUNT---------


@app.route("/delete/<int:user_id>")
def delete_user(user_id):
    ex_user = User.query.get(user_id)
    db.session.delete(ex_user)
    db.session.commit()
    # return render_template("index.html")


# ------RUN APP----------------
if __name__ == "__main__":
    app.run(debug=True)
