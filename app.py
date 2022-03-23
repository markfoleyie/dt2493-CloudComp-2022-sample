"""
A Basic Blogging App: API/Database access using Flask, SQLAlchemy and Tkinter

The task

Create a basic blogging app that allows a user to register and create blog posts. The following rules apply:

* Anyone can register. First Name, Last Name and Password are required
  *    The password should be stored as a cryptographic hash.
  *    A user email should be generated in the form first_name.last_name@tudublin.ie
  *    Log in is authorised by the use of a unique token. Use uuid4 to generate this
  *    A user may be an administrator. This should be indicated by a boolean on registration.
* Any registered and logged in user can create blog posts.
* Each post belongs to one category.
* An administrator can create, update and delete categories.
* Once created, posts cannot be edited or deleted.
* Anyone, whether registered or not, can read any post.
* Anyone, whether registered or not, can read a list of categories.

You will need to...

* Create a database backend. Any database will do, Sqlite, MySQL, PostgreSQL - whatever is installed on your computer.
* Create a Flask app (the Blogging App). This will control access to the database (via SQLAlchemy), and send data
to/from the DB in JSON format (the API component)
  *    All data going to/from the back-end should be in JSON format
* Create a front-end app. This should have a GUI and should be the only means by which the Blogging App is accessed.
* The GUI should handle all the requirements set out above.

Mark Foley,
March 2021.
"""

from functools import wraps

from flask import Flask, jsonify, request
from flask_migrate import Migrate
from flask_restful import Resource, Api, reqparse
from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jwt
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import current_user
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager


from models import db, User, Category, Post
import json
import uuid

app = Flask(__name__)
app.config.from_pyfile("instance/config.py", silent=True)
jwt = JWTManager(app)
db.init_app(app)
migrate = Migrate(app, db)
api = Api(app)


# Register a callback function that takes whatever object is passed in as the
# identity when creating JWTs and converts it to a JSON serializable format.
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


# Register a callback function that loads a user from your database whenever
# a protected route is accessed. This should return any python object on a
# successful lookup, or None if the lookup failed for any reason.
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()


# Here is a custom decorator that verifies the JWT is present in the request,
# as well as insuring that the JWT has a claim indicating that this user is
# an administrator
def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            claims = get_jwt()
            if claims["is_admin"]:
                return fn(*args, **kwargs)
            else:
                return jsonify(message="Admins only!"), 403

        return decorator

    return wrapper


def check_incoming_user(request):
    try:
        incoming_data = check_incoming_data(request)
        if not incoming_data:
            raise ValueError("Invalid data")

        if "username" not in incoming_data:
            raise ValueError("Missing username")

        if "password" not in incoming_data:
            raise ValueError("Missing password")

        return incoming_data
    except Exception as e:
        return False


def check_incoming_data(request):
    try:
        if request.get_json():
            incoming_data = request.get_json()
        else:
            incoming_data = request.data.decode(encoding="utf-8")
            incoming_data = json.dumps(incoming_data)

        return incoming_data
    except Exception as e:
        return False


class HelloWorld(Resource):
    def get(self):
        return {'greeting': 'Welcome to Blogger'}


class Register(Resource):
    def post(self):
        try:
            incoming_data = check_incoming_user(request)
            if not incoming_data:
                raise ValueError("Invalid User data")

            plain_password = incoming_data.pop("password")
            hashed_password = User.create_password_hash(plain_password)
            if not hashed_password:
                raise ValueError("Password error")

            new_user = User(**incoming_data)
            new_user.password = hashed_password

            db.session.add(new_user)
            db.session.commit()

            return incoming_data, 201

        except Exception as e:
            return {"error": f"{e}"}, 400


class Login(Resource):
    def post(self):
        try:
            incoming_data = check_incoming_user(request)
            if not incoming_data:
                raise ValueError("Invalid User data")

            user = db.session.query(User).filter_by(username=incoming_data["username"]).one_or_none()
            if not user:
                raise ValueError("Couldn't get user from database")

            if not user.password_is_verified(incoming_data['password']):
                raise ValueError("Invalid password")

            access_token = create_access_token(
                identity=user,
                additional_claims={"is_admin": user.is_admin}
            )
            # access_token = create_access_token(identity=user)
            refresh_token = create_refresh_token(identity=user)
            # return {"user": user.as_dict_short, "access_token": access_token}, 200
            return {"refresh": refresh_token, "access": access_token}, 200

        except Exception as e:
            return {"error": f"{e}"}, 400


class UserMe(Resource):
    @jwt_required()
    def get(self):
        try:
            return current_user.as_dict_short, 200
        except Exception as e:
            return {"error": f"{e}"}, 400


class MakePost(Resource):
    @jwt_required()
    def post(self):
        try:
            incoming_data = check_incoming_data(request)
            if not incoming_data:
                raise ValueError("Invalid User data")

            post_dict = {
                "owner_id": current_user.id,
                "category_id": incoming_data["category_id"],
                "title": incoming_data["title"],
                "content": incoming_data["content"]
            }
            new_post = Post(**post_dict)
            db.session.add(new_post)
            db.session.commit()

            return incoming_data, 201
        except Exception as e:
            return {"error": f"{e}"}, 400


class ManageCategory(Resource):
    @jwt_required()
    @admin_required()
    def post(self):
        try:
            incoming_data = check_incoming_data(request)
            if not incoming_data:
                raise ValueError("Invalid User data")
            if not current_user.is_admin:
                raise ValueError("User not authorized - must be admin")

            post_dict = {
                "name": incoming_data["name"],
                "hashtag": incoming_data["hashtag"],
                "description": incoming_data["description"]
            }
            new_post = Category(**post_dict)
            db.session.add(new_post)
            db.session.commit()

            return incoming_data, 201
        except Exception as e:
            return {"error": f"{e}"}, 400

    @jwt_required()
    @admin_required()
    def patch(self, category_id):
        try:
            incoming_data = check_incoming_data(request)
            if not incoming_data:
                raise ValueError("Invalid User data")
            if not current_user.is_admin:
                raise ValueError("User not authorized - must be admin")

            cat = db.session.query(Category).filter_by(id=category_id).first() or None

            for k, v in incoming_data.items():
                setattr(cat, k, v)

            db.session.commit()

            return incoming_data, 200

        except Exception as e:
            return {"error": f"{e}"}, 400

    @jwt_required()
    @admin_required()
    def delete(self, category_id):
        try:
            cat = db.session.query(Category).filter_by(id=category_id).first() or None

            db.session.delete(cat)
            db.session.commit()

            return {"message": "category deleted"}, 200

        except Exception as e:
            return {"error": f"{e}"}, 400


class ListPosts(Resource):
    def get(self):
        try:
            posts_list = []
            posts = db.session.query(Post).all()
            for post in posts:
                posts_list.append(post.as_dict)

            return posts_list, 200

        except Exception as e:
            return {"error": f"{e}"}, 400


class ListCategories(Resource):
    def get(self):
        try:
            cats_list = []
            cats = db.session.query(Category).all()
            for cat in cats:
                cats_list.append(cat.as_dict)

            return cats_list, 200

        except Exception as e:
            return {"error": f"{e}"}, 400


# All resources (routes) added here

SITE_PREFIX = "/blogger"
api.add_resource(HelloWorld, f"{SITE_PREFIX}/")
api.add_resource(Register, f"{SITE_PREFIX}/register/")
api.add_resource(Login, f"{SITE_PREFIX}/login/")
api.add_resource(UserMe, f"{SITE_PREFIX}/user/me/")
api.add_resource(MakePost, f"{SITE_PREFIX}/post/")
api.add_resource(ManageCategory, f"{SITE_PREFIX}/category/", f"{SITE_PREFIX}/category/<int:category_id>/")
api.add_resource(ListPosts, f"{SITE_PREFIX}/posts/")
api.add_resource(ListCategories, f"{SITE_PREFIX}/categories/")

if __name__ == '__main__':
    app.run()