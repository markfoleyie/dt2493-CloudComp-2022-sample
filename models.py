from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
import bcrypt

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), unique=True)
    first_name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    password = db.Column(db.LargeBinary(), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created = db.Column(db.DateTime(timezone=True), server_default=func.now())
    updated = db.Column(db.DateTime(timezone=True), onupdate=func.now())

    @property
    def email(self):
        return f"{self.first_name}.{self.last_name}@tudublin.ie"

    @property
    def name(self):
        return f"{self.first_name} {self.last_name}"

    @property
    def as_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email": self.email,
            "is_admin": self.is_admin,
            "created": self.created.isoformat() if self.created else None,
            "updated": self.updated.isoformat() if self.updated else None
        }

    @property
    def as_dict_short(self):
        return {
            "name": self.name,
            "email": self.email,
            "is_admin": self.is_admin,
        }

    def __str__(self):
        return self.name

    @staticmethod
    def create_password_hash(plaintext_password):
        if not plaintext_password:
            return None
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(str(plaintext_password).encode("utf-8"), salt)

    def password_is_verified(self, entered_password):
        entered_password = str(entered_password).encode("utf-8")
        return bcrypt.checkpw(entered_password, self.password)


class Category(db.Model):
    __tablename__ = "category"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), unique=True)
    hashtag = db.Column(db.String(20))
    description = db.Column(db.Text)
    created = db.Column(db.DateTime(timezone=True), server_default=func.now())
    updated = db.Column(db.DateTime(timezone=True), onupdate=func.now())

    def __str__(self):
        return f"{self.name} (#{self.hashtag})"

    @property
    def as_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "hashtag": self.hashtag,
            "description": self.description,
            "created": self.created.isoformat() if self.created else None,
            "updated": self.updated.isoformat() if self.updated else None
        }


class Post(db.Model):
    __tablename__ = "post"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey("category.id"), nullable=False)
    title = db.Column(db.String(50))
    created = db.Column(db.DateTime(timezone=True), server_default=func.now())
    updated = db.Column(db.DateTime(timezone=True), onupdate=func.now())
    content = db.Column(db.Text)
    owner = db.relationship(User, backref=db.backref("owner_assoc", cascade="all,delete"))
    category = db.relationship(Category, backref=db.backref("category_assoc", cascade="all,delete"))

    def __str__(self):
        return f"{self.title}"

    @property
    def as_dict(self):
        return {
            "id": self.id,
            "owner": self.owner.as_dict_short,
            "category": self.category.as_dict,
            "title": self.title,
            "content": self.content,
            "created": self.created.isoformat() if self.created else None,
            "updated": self.updated.isoformat() if self.updated else None
        }
