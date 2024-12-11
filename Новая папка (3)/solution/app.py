import hashlib
import datetime

from flask import Flask, request, jsonify
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///prod.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)
db = SQLAlchemy(app)
jwt = JWTManager(app)


class Countries(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    alpha2 = db.Column(db.String(2), nullable=False, unique=True)
    alpha3 = db.Column(db.String(3), nullable=False, unique=True) 
    region = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"<Country {self.name}>"


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    country_code = db.Column(db.String(2), db.ForeignKey('countries.alpha2'), nullable=False) # Added Foreign Key relationship
    is_public = db.Column(db.Boolean, nullable=False)
    phone = db.Column(db.String(15), nullable=True, unique=True) # Added unique constraint
    image = db.Column(db.String(255), nullable=True)
    country = db.relationship('Countries', backref=db.backref('users', lazy=True)) # Added relationship to Countries

    def __init__(self, login, email, password, country_code, is_public, phone=None, image=None):
        self.login = login
        self.email = email
        self.password = generate_password_hash(password)
        self.country_code = country_code
        self.is_public = is_public
        self.phone = phone
        self.image = image

    def __repr__(self):
        return f"<User {self.login}>"


def authenticate_user(login, password):
    user = User.query.filter_by(login=login).first()
    if user and check_password_hash(user.password, password):
        return user
    return None


@app.route('/api/auth/sign-in', methods=['POST'])
def sign_in():
    data = request.json
    login = data.get('login')
    password = data.get('password')

    if not login or not password:
        return jsonify({"reason": "Login and password are required"}), 400

    user = authenticate_user(login, password)
    if user:
        access_token = create_access_token(identity=user.id)
        return jsonify(token=access_token), 200
    else:
        return jsonify({"reason": "Invalid login or password"}), 401


@app.route('/api/auth/register', methods=['POST'])
def register_user():
    data = request.json
    required_fields = ['login', 'email', 'password', 'countryCode', 'isPublic']

    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return jsonify({"reason": f"Missing fields: {', '.join(missing_fields)}"}), 400

    existing_user = User.query.filter(
        (User.login == data['login']) |
        (User.email == data['email']) |
        (User.phone == data.get('phone'))
            ).first()

    if existing_user:
        return jsonify({"reason": "User with this login, email, or phone already exists"}), 409

    try:
        new_user = User(
            login=data['login'],
            email=data['email'],
            password=data['password'],
            country_code=data['countryCode'],
            is_public=data['isPublic'],
            phone=data.get('phone'),
            image=data.get('image')
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        db.session.rollback() # Rollback in case of error
        return jsonify({"reason": f"Registration failed: {str(e)}"}), 500



@app.route('/api/countries', methods=['GET'])
def get_countries():
    regions = request.args.getlist('region')
    query = Countries.query.order_by(Countries.alpha2)
    if regions:
        query = query.filter(Countries.region.in_(regions))

    countries = query.all()
    if not countries:
        return jsonify({"reason": "No countries found for the specified region(s)"}), 404

    return jsonify([{
        "name": country.name,
        "alpha2": country.alpha2,
        "alpha3": country.alpha3,
        "region": country.region
    } for country in countries])


@app.route('/api/countries/<alpha2_code>', methods=['GET'])
def get_country_by_alpha2(alpha2_code):
    country = Countries.query.filter_by(alpha2=alpha2_code).first()
    if not country:
        return jsonify({"reason": "Country not found"}), 404
    return jsonify({
        "name": country.name,
        "alpha2": country.alpha2,
        "alpha3": country.alpha3,
        "region": country.region
    })


@app.route('/api/ping', methods=['GET'])
def ping():
    return "ok", 200


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)