import os
import secrets
import string
import uuid
from threading import Thread
from twilio.request_validator import RequestValidator
import translations
from functools import wraps
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, make_response, request
from flask_jwt_extended import JWTManager, get_jwt, jwt_required, verify_jwt_in_request, create_access_token, \
    create_refresh_token, current_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import null, UniqueConstraint, and_
from sqlalchemy.exc import IntegrityError
from waitress import serve
from werkzeug.security import check_password_hash, generate_password_hash
from apple_push import is_apn_configured, send_apple_push
from messaging import authenticate_user, create_new_conversation_for_action, add_user_to_conversation, send_sms, \
    sms_service_active, auth_token, get_conversation_id

# region Settings

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('MARIADB_URL')

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
jwt = JWTManager(app)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)
migrate = Migrate(app, db, compare_type=True)
alphabet = string.ascii_letters + string.digits

cors_allowed_origins = os.environ.get('CORS_ALLOWED_ORIGINS', '*').split(',')


# endregion

# region Data Model

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    public_id = db.Column(db.String(36), nullable=False)
    username = db.Column(db.String(64), nullable=False, unique=True)
    first_name = db.Column(db.String(64), nullable=False)
    last_name = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(256), nullable=False)
    phone = db.Column(db.String(12), nullable=False)
    admin = db.Column(db.Boolean, default=False)
    push_interval = db.Column(db.Integer, default=15)
    GPSData = db.relationship('GPSData', backref='users', lazy=True)
    deleted = db.Column(db.Boolean, default=False)
    color = db.Column(db.String(7), default="#ff8000")
    is_one_time = db.Column(db.Boolean, default=False)
    experimental = db.Column(db.Boolean, default=False)


class OneTimeCodes(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    code = db.Column(db.String(32), nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    already_used = db.Column(db.Boolean, default=False)


class GPSData(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    longitude = db.Column(db.Float)
    latitude = db.Column(db.Float)
    speed = db.Column(db.Float)
    speed_accuracy = db.Column(db.Float)
    horizontal_accuracy = db.Column(db.Float)
    vertical_accuracy = db.Column(db.Float)
    altitude = db.Column(db.Float)
    course = db.Column(db.Float)
    course_accuracy = db.Column(db.Float)
    time = db.Column(db.Integer)
    action_id = db.Column(db.Integer, db.ForeignKey('actions.id', ondelete="CASCADE"), nullable=True)
    width = db.Column(db.Integer)


class UsersActions(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    action_id = db.Column(db.Integer, db.ForeignKey('actions.id', ondelete="CASCADE"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), primary_key=True)
    UniqueConstraint(action_id, user_id)


class UsersAreas(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    area_id = db.Column(db.Integer, db.ForeignKey('areas.id', ondelete="CASCADE"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), primary_key=True)
    UniqueConstraint(area_id, user_id)


class Actions(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(256))
    longitude = db.Column(db.Float, nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    radius = db.Column(db.Float, nullable=False)
    start_time = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    deleted = db.Column(db.Boolean, default=False)
    areas = db.relationship('Areas', backref='actions', lazy=True)


class TokenBlockList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)


class Areas(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(64))
    action_id = db.Column(db.Integer, db.ForeignKey('actions.id', ondelete="CASCADE"), nullable=False)
    coordinates = db.relationship('Coordinates', backref='areas', lazy=True)


class Coordinates(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    area_id = db.Column(db.Integer, db.ForeignKey('areas.id', ondelete="CASCADE"), nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    order = db.Column(db.Integer, nullable=False)


class Resources(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    public_id = db.Column(db.String(36), nullable=False)
    extension = db.Column(db.String(8), nullable=False)
    data = db.Column(db.LargeBinary(length=4294967295), nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    action_id = db.Column(db.Integer, db.ForeignKey('actions.id', ondelete="CASCADE"), nullable=False)
    time = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(256))
    kind = db.Column(db.Integer)


class Apns(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    token = db.Column(db.String(128), nullable=False, unique=True)
    action_id = db.Column(db.Integer, db.ForeignKey('actions.id', ondelete="CASCADE"), nullable=True)


# endregion

# region jwt & admin methods

def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            try:
                if claims["is_administrator"]:
                    return fn(*args, **kwargs)
            except KeyError:
                return jsonify(msg="Admins only!"), 403

        return decorator

    return wrapper


@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = db.session.query(TokenBlockList.id).filter_by(jti=jti).scalar()
    return token is not None


@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.username


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return Users.query.filter_by(username=identity).one_or_none()


async def delete_device_from_apn(notification_id, response, device_token):
    Apns.query.filter_by(token=device_token).delete()
    db.session.commit()


@app.after_request
def add_header(response):
    if '*' in cors_allowed_origins or request.origin in cors_allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = request.origin
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PATCH, DELETE"
        response.headers['Vary'] = 'Origin'
    response.headers['Access-Control-Allow-Headers'] = 'authorization, content-type'
    response.headers['Content-Type'] = 'application/json'
    return response


def validate_twilio_request(f):
    """Validates that incoming requests genuinely originated from Twilio"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Create an instance of the RequestValidator class
        validator = RequestValidator(auth_token)

        # Validate the request using its URL, POST data,
        # and X-TWILIO-SIGNATURE header
        request_valid = validator.validate(
            # TODO: heroku specific
            request.url.replace("http:/", "https:/"),
            request.form,
            request.headers.get('X-TWILIO-SIGNATURE', ''))

        # Continue processing the request if it's valid, return a 403 error if
        # it's not
        if request_valid:
            return f(*args, **kwargs)
        else:
            return jsonify(msg="not authorized"), 403

    return decorated_function


# endregion

# region Public Routes

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        user = Users.query.filter_by(username=data['username']).first()
        if user:
            return jsonify(msg='username taken')
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = Users(public_id=str(uuid.uuid4()),
                         username=data['username'],
                         password=hashed_password,
                         first_name=data['first_name'],
                         last_name=data['last_name'],
                         phone=data['phone'])
        db.session.add(new_user)
        db.session.commit()
    except KeyError:
        return jsonify(msg='data error'), 400
    return jsonify(msg='registered successfully')


@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    user = Users.query.filter_by(username=auth.username).first()
    if not user or user.deleted:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})
    if request.args.get('admin_required') and request.args.get('admin_required') == "true" and not user.admin:
        return make_response('access forbidden', 403, {'WWW.Authentication': 'Basic realm: "login required"'})
    if check_password_hash(user.password, auth.password):
        if user.admin:
            access_token = create_access_token(identity=user, additional_claims={"is_administrator": True})
            refresh_token = create_refresh_token(identity=user, additional_claims={"is_administrator": True})
        else:
            access_token = create_access_token(identity=user)
            refresh_token = create_refresh_token(identity=user)
        return jsonify(access_token=access_token, refresh_token=refresh_token)
    return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})


@app.route('/login/code', methods=['POST'])
def login_invitation():
    auth = request.authorization
    if not auth or not auth.password:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "password required"'})
    code_in_db = OneTimeCodes.query.filter_by(code=auth.password).first()
    # TODO: ensure invitation link can be only used once!
    # if code_in_db and not code_in_db.already_used:
    if code_in_db:
        user = Users.query.filter_by(id=code_in_db.user_id).first()
        access_token = create_access_token(identity=user)
        refresh_token = create_refresh_token(identity=user)
        code_in_db.already_used = True
        db.session.commit()
        return jsonify(access_token=access_token, refresh_token=refresh_token)
    return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})


# endregion

# region Routes


@app.route("/authorize/twilio", methods=["GET"])
@jwt_required()
def twilio_login():
    identity = request.args.get('identity')
    if identity:
        token = authenticate_user(identity)
        return jsonify(token=token, identity=identity)
    return jsonify(msg="identity not provided"), 400


@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    if current_user.deleted:
        return jsonify(msg="Token has expired")
    if current_user.admin:
        access_token = create_access_token(identity=current_user, additional_claims={"is_administrator": True})
        refresh_token = create_refresh_token(identity=current_user, additional_claims={"is_administrator": True})
    else:
        access_token = create_access_token(identity=current_user)
        refresh_token = create_refresh_token(identity=current_user)
    jti = get_jwt()["jti"]
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlockList(jti=jti, created_at=now))
    db.session.commit()
    return jsonify(access_token=access_token, refresh_token=refresh_token)


@app.route("/register/apn", methods=["POST"])
@jwt_required()
def store_new_apn():
    data = request.get_json()
    new_apn_entry = Apns(token=data['apn'],
                         user_id=current_user.id)
    db.session.add(new_apn_entry)
    db.session.commit()
    return jsonify(msg="apn registered")


@app.route("/actions/<action_id>/join", methods=["PATCH"])
@jwt_required()
def join_action(action_id):
    apns = Apns.query.filter_by(user_id=current_user.id).all()
    for device in apns:
        device.action_id = action_id
    db.session.commit()
    return jsonify(msg="apn activated")


@app.route("/actions/leave", methods=["PATCH"])
@jwt_required()
def leave_action():
    apns = Apns.query.filter_by(user_id=current_user.id).all()
    for device in apns:
        device.action_id = None
    db.session.commit()
    return jsonify(msg="apn deactivated")


@app.route("/users/me", methods=["GET"])
@jwt_required()
def who_am_i():
    return jsonify(
        id=current_user.public_id,
        username=current_user.username,
        phone=current_user.phone,
        one_time_user=current_user.is_one_time,
        first_name=current_user.first_name,
        last_name=current_user.last_name,
        push_interval=current_user.push_interval,
        experimental_features=current_user.experimental
    )


@app.route("/users/update/username", methods=["PATCH"])
@jwt_required()
def change_username():
    data = request.get_json()
    user = Users.query.filter_by(username=data['username']).first()
    if user:
        return jsonify(msg='username taken'), 409
    current_user.username = data['username']
    db.session.commit()
    if current_user.admin:
        access_token = create_access_token(identity=current_user, additional_claims={"is_administrator": True})
        refresh_token = create_refresh_token(identity=current_user, additional_claims={"is_administrator": True})
    else:
        access_token = create_access_token(identity=current_user)
        refresh_token = create_refresh_token(identity=current_user)
    return jsonify(
        username=current_user.username,
        access_token=access_token,
        refresh_token=refresh_token
    )


@app.route("/users/update/password", methods=["PATCH"])
@jwt_required()
def change_password():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    current_user.password = hashed_password
    db.session.commit()
    return jsonify(msg='password changed')


@app.route("/users/update/names", methods=["PATCH"])
@jwt_required()
def change_names():
    data = request.get_json()
    current_user.first_name = data['first_name']
    current_user.last_name = data['last_name']
    db.session.commit()
    return jsonify(msg='names changed', first_name=current_user.first_name, last_name=current_user.last_name)


@app.route("/users/my_areas", methods=["GET"])
@jwt_required()
def get_user_areas():
    my_areas = UsersAreas.query.filter_by(user_id=current_user.id).all()
    areas = [item.area_id for item in my_areas]
    return jsonify(
        areas=areas
    )


@app.route("/users/me/validate", methods=["GET"])
@jwt_required()
def is_token_valid():
    if current_user.deleted:
        return jsonify(msg="Token has expired")
    return jsonify(
        push_interval=current_user.push_interval
    )


@app.route('/users', methods=['GET'])
@jwt_required()
def get_users_basic_info():
    users = Users.query.filter_by(deleted=False).all()
    result = []
    for user in users:
        user_data = {'id': user.public_id,
                     'firstName': user.first_name,
                     'lastName': user.last_name,
                     'phone': user.phone,
                     'color': user.color}
        result.append(user_data)
    return jsonify({'users': result})


@app.route("/actions", methods=["GET"])
@jwt_required()
def get_users_actions():
    my_actions = UsersActions.query.filter_by(user_id=current_user.id).all()
    actions_detail = []
    for action in my_actions:
        details = Actions.query.filter_by(id=action.action_id).first()
        if not details.deleted:
            actions_detail.append(details)
    output = []
    for data_row in actions_detail:
        data = {'id': data_row.id,
                'name': data_row.name,
                'description': data_row.description,
                'longitude': data_row.longitude,
                'latitude': data_row.latitude,
                'radius': data_row.radius,
                'start_time': data_row.start_time,
                'is_active': data_row.is_active}
        output.append(data)
    return jsonify({'actions': output})


@app.route("/areas/<action_id>", methods=["GET"])
@jwt_required()
def get_action_areas(action_id):
    is_my_action = UsersActions.query.filter_by(user_id=current_user.id, action_id=action_id).first()
    if not is_my_action:
        return jsonify(msg="bad action"), 404
    areas = Areas.query.filter_by(action_id=action_id).all()
    output = []
    for area in areas:
        coordinates = []
        coords = Coordinates.query.filter_by(area_id=area.id).all()
        for data_row in coords:
            data = {'longitude': data_row.longitude,
                    'latitude': data_row.latitude,
                    'id': data_row.id,
                    'order': data_row.order}
            coordinates.append(data)
        data = {'area_id': area.id,
                'name': area.name,
                'coordinates': coordinates
                }
        output.append(data)
    return jsonify({'areas': output})


@app.route("/resources/<action_id>", methods=["GET"])
@jwt_required()
def get_action_resources(action_id):
    is_my_action = UsersActions.query.filter_by(user_id=current_user.id, action_id=action_id).first()
    if not is_my_action:
        return jsonify(msg="bad action"), 404
    resources = Resources.query.with_entities(Resources.id,
                                              Resources.public_id,
                                              Resources.time,
                                              Resources.description,
                                              Resources.extension,
                                              Resources.latitude,
                                              Resources.longitude,
                                              Resources.name,
                                              Resources.public_id,
                                              Resources.user_id,
                                              Resources.kind).filter_by(action_id=action_id).all()
    output = []
    for item in resources:
        user = Users.query.filter_by(id=item.user_id).first()
        data = {'id': item.id,
                'uuid': item.public_id,
                'time': item.time,
                'description': item.description,
                'ext': item.extension,
                'latitude': item.latitude,
                'longitude': item.longitude,
                'name': item.name,
                'userID': user.public_id,
                'kind': item.kind
                }
        output.append(data)
    return jsonify({'resources': output})


@app.route("/resources/blob", methods=["GET"])
@jwt_required()
def get_blob_data():
    if request.args.get('uuid'):
        try:
            public_id = request.args.get('uuid')
            content = Resources.query.filter_by(public_id=public_id).first()
            return content.data
        except AttributeError:
            return jsonify(msg="resource not found"), 404
    else:
        return jsonify(msg="uuid not provided"), 400


@app.route("/logout", methods=["DELETE"])
@jwt_required()
def revoke_token():
    jti = get_jwt()["jti"]
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlockList(jti=jti, created_at=now))
    db.session.commit()
    return jsonify(msg="JWT revoked")


@app.route("/revoke/apn", methods=["DELETE"])
@jwt_required()
def delete_apn_after_logout():
    data = request.get_json()
    Apns.query.filter_by(token=data["apn"]).delete()
    db.session.commit()
    return jsonify(msg="apn unregistered")


@app.route('/locations', methods=['POST'])
@jwt_required()
def add_location():
    try:
        data = request.get_json()
        action = (Actions.query.filter_by(id=data['action']).first()).id
        if not action:
            action = null
        new_location = GPSData(longitude=data['longitude'],
                               latitude=data['latitude'],
                               time=data['time'],
                               speed=data['speed'],
                               course_accuracy=data['course_accuracy'],
                               speed_accuracy=data['speed_accuracy'],
                               horizontal_accuracy=data['horizontal_accuracy'],
                               vertical_accuracy=data['vertical_accuracy'],
                               altitude=data['altitude'],
                               course=data['course'],
                               user_id=current_user.id,
                               action_id=action,
                               width=data['width'])
        db.session.add(new_location)
        db.session.commit()
        return jsonify(msg="data saved")
    except KeyError:
        return jsonify(msg="bad data"), 400


@app.route('/actions/resources', methods=['POST'])
@jwt_required()
def add_resource():
    try:
        data = request.get_json()
        action_id = (Actions.query.filter_by(id=data['action']).first()).id
        if not action_id:
            return jsonify(msg="bad data"), 400
        new_resource = Resources(public_id=data['uuid'],
                                 extension=data['extension'],
                                 data=data['blob'].encode('ascii'),
                                 longitude=data['longitude'],
                                 latitude=data['latitude'],
                                 user_id=current_user.id,
                                 action_id=action_id,
                                 time=data['time'],
                                 name=data['name'],
                                 kind=data['kind'],
                                 description=data['description'])
        db.session.add(new_resource)
        db.session.commit()
        # ----sending push notifications----
        apns = Apns.query.filter_by(action_id=action_id).all()
        thread = Thread(target=send_apple_push, args=(app.root_path,
                                                      apns,
                                                      translations.new_point_added,
                                                      "new_resource",
                                                      delete_device_from_apn))
        thread.start()
        return jsonify(msg="data saved", id=new_resource.id, uid=current_user.public_id)
    except (KeyError, AttributeError):
        return jsonify(msg="bad data"), 400


# endregion

# region Admin Routes

@app.route('/register/one_time', methods=['POST'])
@jwt_required()
@admin_required()
def register_one_time():
    try:
        data = request.get_json()
        new_uuid = str(uuid.uuid4())
        password = ''.join(secrets.choice(alphabet) for _ in range(16))
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = Users(public_id=new_uuid,
                         username=new_uuid,
                         password=hashed_password,
                         first_name='-',
                         last_name='-',
                         phone=data['phone'],
                         is_one_time=True)
        db.session.add(new_user)
        db.session.commit()
        code = secrets.token_hex(3)
        new_code = OneTimeCodes(code=code,
                                user_id=new_user.id)
        db.session.add(new_code)
        db.session.commit()
    except KeyError:
        return jsonify(msg='data error'), 400
    return jsonify(msg='registered successfully', invitaion_code=code)


@app.route('/notifications/send/all', methods=['POST'])
@jwt_required()
@admin_required()
def send_push_to_all():
    if not is_apn_configured:
        return jsonify(msg='APN is not configured'), 501
    data = request.get_json()
    if data["msg"] and data["msg"] != "":
        msg = data["msg"]
    else:
        return jsonify(msg='message cannot be empty!'), 400
    apns = Apns.query.all()
    thread = Thread(target=send_apple_push, args=(app.root_path,
                                                  apns,
                                                  msg,
                                                  "to_all",
                                                  delete_device_from_apn))
    thread.start()
    return jsonify(msg='sending started')


@app.route('/notifications/send/action/<action_id>', methods=['POST'])
@jwt_required()
@admin_required()
def send_push_to_all_in_action(action_id):
    if not is_apn_configured:
        return jsonify(msg='APN is not configured'), 501
    data = request.get_json()
    if data["msg"] and data["msg"] != "":
        msg = data["msg"]
    else:
        return jsonify(msg='message cannot be empty!'), 400
    apns = Apns.query.filter_by(action_id=action_id).all()
    thread = Thread(target=send_apple_push, args=(app.root_path,
                                                  apns,
                                                  msg,
                                                  "to_action",
                                                  delete_device_from_apn))
    thread.start()
    return jsonify(msg='sending started')


@app.route('/notifications/send/area/<area_id>', methods=['POST'])
@jwt_required()
@admin_required()
def send_push_to_all_in_area(area_id):
    if not is_apn_configured:
        return jsonify(msg='APN is not configured'), 501
    data = request.get_json()
    if data["msg"] and data["msg"] != "":
        msg = data["msg"]
    else:
        return jsonify(msg='message cannot be empty!'), 400
    area = Areas.query.filter_by(id=area_id).first()
    if not area:
        return jsonify(msg="area not found"), 404
    apns = Apns.query.filter_by(action_id=area.action_id).all()
    thread = Thread(target=send_apple_push, args=(app.root_path,
                                                  apns,
                                                  msg,
                                                  "to_area",
                                                  delete_device_from_apn))
    thread.start()
    return jsonify(msg='sending started')


@app.route('/notifications/send/user/<user_id>', methods=['POST'])
@jwt_required()
@admin_required()
def send_push_to_one_user(user_id):
    if not is_apn_configured:
        return jsonify(msg='APN is not configured'), 501
    data = request.get_json()
    if data["msg"] and data["msg"] != "":
        msg = data["msg"]
    else:
        return jsonify(msg='message cannot be empty!'), 400
    apns = Apns.query.filter_by(user_id=user_id).all()
    thread = Thread(target=send_apple_push, args=(app.root_path, apns, msg, "to_user", delete_device_from_apn))
    thread.start()
    return jsonify(msg='sending started')


@app.route('/codes/generate/', methods=['POST'])
@jwt_required()
@admin_required()
def generate_code_for_onetime_user():
    data = request.get_json()
    user = Users.query.filter_by(id=data["user"]).first()
    if not user:
        return jsonify(msg="user not found"), 404
    code = secrets.token_hex(3)
    new_code = OneTimeCodes(code=code,
                            user_id=user.id)
    db.session.add(new_code)
    db.session.commit()
    return jsonify(msg='new code generated', invitaion_code=code)


@app.route('/sms/send/invite', methods=['POST'])
@jwt_required()
@admin_required()
def send_sms_invite():
    if not sms_service_active:
        return jsonify(msg="sms service is not active"), 501
    data = request.get_json()
    number_with_prefix = data["number_with_prefix"]
    login_code = data["login_code"]
    if number_with_prefix and login_code:
        thread = Thread(target=send_sms, args=(number_with_prefix, translations.sms_invite, login_code))
        thread.start()
        return jsonify(msg="sending started")
    return jsonify(msg="bad request"), 400


@app.route('/codes/delete/<code_id>', methods=['DELETE'])
@jwt_required()
@admin_required()
def delete_code_by_its_id(code_id):
    try:
        OneTimeCodes.query.filter_by(id=code_id).delete()
        db.session.commit()
    except KeyError:
        return jsonify(msg="bad id"), 400
    return jsonify(msg='code deleted')


@app.route("/users/add_admin", methods=["PATCH"])
@jwt_required()
@admin_required()
def add_admin():
    data = request.get_json()
    user = Users.query.filter_by(id=data["user"]).first()
    if not user:
        return jsonify(msg="bad user"), 404
    user.admin = True
    db.session.commit()
    return jsonify(msg="admin added")


@app.route("/users/set_color", methods=["PATCH"])
@jwt_required()
@admin_required()
def set_admin():
    data = request.get_json()
    user = Users.query.filter_by(id=data["user"]).first()
    color = data["color"]
    if not user or not color:
        return jsonify(msg="bad data"), 404
    user.color = color
    db.session.commit()
    return jsonify(msg="color changed")


@app.route("/users/<user_id>", methods=["DELETE"])
@jwt_required()
@admin_required()
def delete_user(user_id):
    user = Users.query.filter_by(id=user_id).first()
    if not user:
        return jsonify(msg="bad user"), 404
    user.deleted = True
    OneTimeCodes.query.filter_by(user_id=user_id).delete()
    Apns.query.filter_by(user_id=user_id).delete()
    db.session.commit()
    return jsonify(msg="user marked as removed")


@app.route("/actions/<action_id>", methods=["DELETE"])
@jwt_required()
@admin_required()
def delete_action(action_id):
    action = Actions.query.filter_by(id=action_id).first()
    if not action:
        return jsonify(msg="bad action"), 404
    action.deleted = True
    Apns.query.filter_by(action_id=action_id).delete()
    db.session.commit()
    return jsonify(msg="action marked as removed")


@app.route("/users/set_interval", methods=["PATCH"])
@jwt_required()
@admin_required()
def set_interval():
    try:
        data = request.get_json()
        user = Users.query.filter_by(id=data["user"]).first()
        if not user:
            return jsonify(msg="bad user"), 404
        user.push_interval = data["interval"]
    except KeyError:
        return jsonify(msg="bad interval data"), 400
    db.session.commit()
    return jsonify(msg="interval set")


@app.route("/actions/add_user", methods=["POST"])
@jwt_required()
@admin_required()
def add_user_to_action():
    try:
        data = request.get_json()
        user = Users.query.filter_by(id=data["user"]).first()
        action = Actions.query.filter_by(id=data["action"]).first()
        if user and action:
            new_entry = UsersActions(action_id=action.id,
                                     user_id=user.id)
            db.session.add(new_entry)
            db.session.commit()
            add_user_to_conversation(action.id, user.public_id)
            # ----sending push notifications----
            apns = Apns.query.filter_by(user_id=user.id).all()
            thread = Thread(target=send_apple_push, args=(app.root_path,
                                                          apns,
                                                          translations.new_action_available,
                                                          "new_action",
                                                          delete_device_from_apn))
            thread.start()
            return jsonify(msg="user added")
        return jsonify(msg="bad user or/and action"), 404
    except KeyError:
        return jsonify(msg="bad data"), 400
    except IntegrityError:
        return jsonify(msg="user may be already added!"), 400


@app.route("/areas/add_user", methods=["POST"])
@jwt_required()
@admin_required()
def add_user_to_area():
    try:
        data = request.get_json()
        user = Users.query.filter_by(id=data["user"]).first()
        area = Areas.query.filter_by(id=data["area"]).first()
        if not user or not area:
            return jsonify(msg="bad user or/and area"), 404
        is_area_in_users_action = UsersActions.query.filter_by(user_id=user.id, action_id=area.action_id).first()
        if is_area_in_users_action and user and area:
            new_entry = UsersAreas(area_id=area.id,
                                   user_id=user.id)
            db.session.add(new_entry)
            db.session.commit()
            # ----sending push notifications----
            apns = Apns.query.filter_by(user_id=user.id).all()
            thread = Thread(target=send_apple_push, args=(app.root_path,
                                                          apns,
                                                          translations.new_area_for_you,
                                                          "new_area",
                                                          delete_device_from_apn))
            thread.start()
            return jsonify(msg="user added")
        return jsonify(msg="area is not part of users actions"), 404
    except KeyError:
        return jsonify(msg="bad data"), 400
    except IntegrityError:
        return jsonify(msg="user may be already added!"), 400


@app.route("/areas/del_user", methods=["DELETE"])
@jwt_required()
@admin_required()
def remove_user_from_area():
    data = request.get_json()
    UsersAreas.query.filter_by(user_id=data["user"], area_id=data["area"]).delete()
    db.session.commit()
    return jsonify(msg="user removed from area")


@app.route("/areas/<action_id>/rich", methods=["GET"])
@jwt_required()
@admin_required()
def get_action_areas_admin(action_id):
    areas = Areas.query.filter_by(action_id=action_id).all()
    output = []
    for area in areas:
        coordinates = []
        coords = Coordinates.query.filter_by(area_id=area.id).all()
        for data_row in coords:
            data = {'longitude': data_row.longitude,
                    'latitude': data_row.latitude,
                    'id': data_row.id,
                    'order': data_row.order}
            coordinates.append(data)
        data = {'area_id': area.id,
                'name': area.name,
                'coordinates': coordinates
                }
        output.append(data)
    return jsonify({'areas': output})


@app.route('/users/rich', methods=['GET'])
@jwt_required()
@admin_required()
def get_users():
    users = Users.query.filter_by(deleted=False).all()
    result = []
    for user in users:
        user_data = {'id': user.id,
                     'public_id': user.public_id,
                     'username': user.username,
                     'first_name': user.first_name,
                     'last_name': user.last_name,
                     'phone': user.phone,
                     'admin': user.admin,
                     'interval': user.push_interval,
                     'is_one_time': user.is_one_time,
                     'color': user.color}
        result.append(user_data)
    return jsonify({'users': result})


@app.route('/users/deleted/rich', methods=['GET'])
@jwt_required()
@admin_required()
def get_deleted_users():
    users = Users.query.filter_by(deleted=True).all()
    result = []
    for user in users:
        user_data = {'id': user.id,
                     'public_id': user.public_id,
                     'username': user.username,
                     'first_name': user.first_name,
                     'last_name': user.last_name,
                     'phone': user.phone,
                     'admin': user.admin,
                     'interval': user.push_interval,
                     'is_one_time': user.is_one_time,
                     'color': user.color}
        result.append(user_data)
    return jsonify({'users': result})


@app.route("/actions/all", methods=["GET"])
@jwt_required()
@admin_required()
def get_all_actions():
    actions = Actions.query.filter_by(deleted=False).all()
    output = []
    for data_row in actions:
        data = {'id': data_row.id,
                'name': data_row.name,
                'description': data_row.description,
                'longitude': data_row.longitude,
                'latitude': data_row.latitude,
                'radius': data_row.radius,
                'start_time': data_row.start_time,
                'is_active': data_row.is_active}
        output.append(data)
    return jsonify({'actions': output})


@app.route("/actions/deleted/all", methods=["GET"])
@jwt_required()
@admin_required()
def get_all_deleted_actions():
    actions = Actions.query.filter_by(deleted=True).all()
    output = []
    for data_row in actions:
        data = {'id': data_row.id,
                'name': data_row.name,
                'description': data_row.description,
                'longitude': data_row.longitude,
                'latitude': data_row.latitude,
                'radius': data_row.radius,
                'start_time': data_row.start_time,
                'is_active': data_row.is_active}
        output.append(data)
    return jsonify({'actions': output})


@app.route('/actions/<action_id>', methods=['GET'])
@jwt_required()
@admin_required()
def get_action_details(action_id):
    try:
        action = Actions.query.filter_by(id=action_id).first()
        output = {
            'name': action.name,
            'description': action.description,
            'longitude': action.longitude,
            'latitude': action.latitude,
            'radius': action.radius,
            'start_time': action.start_time,
            'is_active': action.is_active}
        return jsonify({action.id: output})
    except KeyError:
        return jsonify(msg="bad action id"), 400


@app.route("/actions/<action_id>/users", methods=["GET"])
@jwt_required()
@admin_required()
def get_action_users(action_id):
    try:
        users = UsersActions.query.filter_by(action_id=action_id).all()
        output = []
        for user in users:
            result = Users.query.filter_by(id=user.user_id).first()
            if not result.deleted:
                output.append(result.public_id)
        return jsonify({'users': output})
    except KeyError:
        return jsonify(msg="bad action id"), 400


@app.route("/areas/<area_id>/users", methods=["GET"])
@jwt_required()
@admin_required()
def get_area_users(area_id):
    try:
        users = UsersAreas.query.filter_by(area_id=area_id).all()
        output = []
        for user in users:
            result = Users.query.filter_by(id=user.user_id).first()
            if not result.deleted:
                output.append(result.public_id)
        return jsonify({'users': output})
    except KeyError:
        return jsonify(msg="bad area id"), 400


@app.route('/users/codes', methods=['GET'])
@jwt_required()
@admin_required()
def get_invitation_codes():
    codes = OneTimeCodes.query.all()
    result = []
    for code in codes:
        invitation_data = {'id': code.id,
                           'user_id': code.user_id,
                           'code': code.code}
        result.append(invitation_data)
    return jsonify({'codes': result})


@app.route('/locations', methods=['GET'])
@jwt_required()
@admin_required()
def get_locations():
    filter_type = 0
    filter_value = 1
    try:
        if request.args.get('id') or request.args.get('timestamp'):
            if request.args.get('id'):
                filter_type = 1
                filter_value = int(request.args.get('id'))
            else:
                filter_type = 2
                filter_value = int(request.args.get('timestamp'))
        if filter_type == 0:
            gps_data = GPSData.query.all()
        elif filter_type == 1:
            gps_data = GPSData.query.filter(GPSData.id > filter_value)
        else:
            gps_data = GPSData.query.filter(GPSData.time > filter_value)
    except KeyError:
        return jsonify(msg="bad data"), 400
    except ValueError:
        return jsonify(msg="bad params"), 400
    output = []
    for data_row in gps_data:
        data = {'id': data_row.id,
                'longitude': data_row.longitude,
                'latitude': data_row.latitude,
                'time': data_row.time,
                'user': data_row.user_id,
                'speed': data_row.speed,
                'speed_accuracy': data_row.speed_accuracy,
                'horizontal_accuracy': data_row.horizontal_accuracy,
                'vertical_accuracy': data_row.vertical_accuracy,
                'altitude': data_row.altitude,
                'course': data_row.course,
                'course_accuracy': data_row.course_accuracy,
                'action': data_row.action_id}
        output.append(data)
    return jsonify({'locations': output})


@app.route("/resources/<action_id>/all", methods=["GET"])
@jwt_required()
@admin_required()
def get_all_action_resources(action_id):
    resources = Resources.query.with_entities(Resources.id,
                                              Resources.public_id,
                                              Resources.time,
                                              Resources.description,
                                              Resources.extension,
                                              Resources.latitude,
                                              Resources.longitude,
                                              Resources.name,
                                              Resources.public_id,
                                              Resources.user_id,
                                              Resources.kind).filter_by(action_id=action_id).all()
    output = []
    for item in resources:
        user = Users.query.filter_by(id=item.user_id).first()
        data = {'id': item.id,
                'uuid': item.public_id,
                'time': item.time,
                'description': item.description,
                'ext': item.extension,
                'latitude': item.latitude,
                'longitude': item.longitude,
                'name': item.name,
                'userID': user.public_id,
                'kind': item.kind
                }
        output.append(data)
    return jsonify({'resources': output})


@app.route('/locations/<action_id>/<user_id>', methods=['GET'])
@jwt_required()
@admin_required()
def get_locations_by_action_user(action_id, user_id):
    filter_type = 0
    filter_value = 1
    try:
        if request.args.get('id') or request.args.get('timestamp'):
            if request.args.get('id'):
                filter_type = 1
                filter_value = int(request.args.get('id'))
            else:
                filter_type = 2
                filter_value = int(request.args.get('timestamp'))
        if filter_type == 0:
            locations = GPSData.query.filter_by(action_id=action_id, user_id=user_id).all()
        elif filter_type == 1:
            locations = GPSData.query.filter(and_(GPSData.action_id == action_id,
                                                  GPSData.id > filter_value,
                                                  GPSData.user_id == user_id))
        else:
            locations = GPSData.query.filter(and_(GPSData.action_id == action_id,
                                                  GPSData.time > filter_value,
                                                  GPSData.user_id == user_id))
    except KeyError:
        return jsonify(msg="bad data"), 400
    except ValueError:
        return jsonify(msg="bad params"), 400
    output = []
    for data_row in locations:
        data = {'id': data_row.id,
                'longitude': data_row.longitude,
                'latitude': data_row.latitude,
                'time': data_row.time,
                'user': data_row.user_id,
                'speed': data_row.speed,
                'speed_accuracy': data_row.speed_accuracy,
                'horizontal_accuracy': data_row.horizontal_accuracy,
                'vertical_accuracy': data_row.vertical_accuracy,
                'altitude': data_row.altitude,
                'course': data_row.course,
                'course_accuracy': data_row.course_accuracy,
                'action': data_row.action_id}
        output.append(data)
    return jsonify({'locations': output})


@app.route('/locations/<action_id>', methods=['GET'])
@jwt_required()
@admin_required()
def get_locations_by_action(action_id):
    filter_type = 0
    filter_value = 1
    try:
        if request.args.get('id') or request.args.get('timestamp'):
            if request.args.get('id'):
                filter_type = 1
                filter_value = int(request.args.get('id'))
            else:
                filter_type = 2
                filter_value = int(request.args.get('timestamp'))
        if filter_type == 0:
            locations = GPSData.query.filter_by(action_id=action_id).all()
        elif filter_type == 1:
            locations = GPSData.query.filter(and_(GPSData.action_id == action_id, GPSData.id > filter_value))
        else:
            locations = GPSData.query.filter(and_(GPSData.action_id == action_id, GPSData.time > filter_value))
    except KeyError:
        return jsonify(msg="bad data"), 400
    except ValueError:
        return jsonify(msg="bad params"), 400
    output = []
    for data_row in locations:
        data = {'id': data_row.id,
                'longitude': data_row.longitude,
                'latitude': data_row.latitude,
                'time': data_row.time,
                'user': data_row.user_id,
                'speed': data_row.speed,
                'speed_accuracy': data_row.speed_accuracy,
                'horizontal_accuracy': data_row.horizontal_accuracy,
                'vertical_accuracy': data_row.vertical_accuracy,
                'altitude': data_row.altitude,
                'course': data_row.course,
                'course_accuracy': data_row.course_accuracy,
                'action': data_row.action_id}
        output.append(data)
    return jsonify({'locations': output})


@app.route('/actions', methods=['POST'])
@jwt_required()
@admin_required()
def add_action():
    try:
        data = request.get_json()
        new_action = Actions(name=data['name'],
                             description=data['description'],
                             longitude=data['longitude'],
                             latitude=data['latitude'],
                             radius=data['radius'],
                             start_time=data['start_time'])
    except KeyError:
        return jsonify(msg="bad data"), 400
    db.session.add(new_action)
    db.session.commit()
    create_new_conversation_for_action(new_action.id)
    return jsonify(created_id=new_action.id)


@app.route('/actions/toggle', methods=['PATCH'])
@jwt_required()
@admin_required()
def start_action():
    try:
        data = request.get_json()
        action = Actions.query.filter_by(id=data["action"]).first()
        if action.deleted:
            return jsonify(msg="action is deleted, cannot change state"), 404
        action.is_active = data["is_active"]
    except KeyError:
        return jsonify(msg="bad data"), 400
    db.session.commit()
    # ----sending push notifications----
    if action.is_active:
        # create_new_conversation_for_action(action.id) # TODO: we have already done it while creating new action
        users_in_action = UsersActions.query.filter_by(action_id=action.id).all()
        users_ids = [item.user_id for item in users_in_action]
        apns = Apns.query.filter(Apns.user_id.in_(users_ids)).all()
        thread = Thread(target=send_apple_push, args=(app.root_path,
                                                      apns,
                                                      translations.action_is_active_now,
                                                      "now_active",
                                                      delete_device_from_apn))
        thread.start()
    return jsonify(msg="action status set")


@app.route('/locations/<user_id>', methods=['DELETE'])
@jwt_required()
@admin_required()
def delete_location(user_id):
    try:
        GPSData.query.filter_by(user_id=user_id).delete()
        db.session.commit()
    except KeyError:
        return jsonify(msg="bad user"), 400
    return jsonify(msg='location data deleted')


@app.route('/actions/del_user', methods=['DELETE'])
@jwt_required()
@admin_required()
def delete_user_from_action():
    try:
        data = request.get_json()
        user = Users.query.filter_by(id=data['user']).first()
        UsersActions.query.filter_by(user_id=user.id, action_id=data['action']).delete()
        areas = Areas.query.filter_by(action_id=data['action']).all()
        for area in areas:
            UsersAreas.query.filter_by(area_id=area.id, user_id=user.id).delete()
        db.session.commit()
    except KeyError:
        return jsonify(msg="bad data"), 400
    return jsonify(msg='user removed from action')


@app.route('/areas/<area_id>', methods=['DELETE'])
@jwt_required()
@admin_required()
def delete_area_with_all_data(area_id):
    try:
        Areas.query.filter_by(id=area_id).delete()
        db.session.commit()
    except KeyError:
        return jsonify(msg="bad area"), 400
    return jsonify(msg='area removed')


@app.route('/actions/<action_id>/add_area', methods=['POST'])
@jwt_required()
@admin_required()
def add_area(action_id):
    try:
        data = request.get_json()
        area = Areas(name=data['name'],
                     action_id=action_id)
        db.session.add(area)
        db.session.commit()
        for coords in data['coordinates']:
            coordinates = Coordinates(latitude=coords['latitude'],
                                      longitude=coords['longitude'],
                                      order=coords['order'],
                                      area_id=area.id)
            db.session.add(coordinates)
        db.session.commit()
        return jsonify(msg='new area added', area_id=area.id)
    except KeyError:
        return jsonify(msg='something went wrong...'), 500
    except IntegrityError:
        return jsonify(msg='something went wrong...'), 500


# endregion

# region webhooks

# TODO: not gonna work outside heroku (need configuration on twilio console)
@app.route('/webhook/twilio/chat', methods=['POST'])
@validate_twilio_request
def new_chat_message_webhook():
    if not is_apn_configured:
        return jsonify(msg='APN is not configured'), 501
    user = Users.query.filter_by(public_id=request.form.getlist('Author')[0]).first()
    body = translations.new_chat[translations.get_current_locales()] + request.form.getlist('Body')[0]
    action = get_conversation_id(request.form.getlist('ConversationSid')[0])
    apns = Apns.query.filter(and_(Apns.action_id == str(action), Apns.user_id != user.id)).all()
    thread = Thread(target=send_apple_push, args=(app.root_path,
                                                  apns,
                                                  body,
                                                  "from_chat",
                                                  delete_device_from_apn))
    thread.start()
    return jsonify(msg='sending started')


# endregion


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5555))
    host = os.environ.get('HOST', '0.0.0.0')
    debug = os.environ.get('DEBUG', 'False').lower() in ('true', '1')

    if debug:
        app.run(host=host, debug=False, port=port)
    else:
        serve(app, host=host, port=port)
