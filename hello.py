from flask import Flask, render_template, flash, request
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from wtforms import StringField, BooleanField, PasswordField, SubmitField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# SQLlight URI
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:F24850346c!@localhost/our_users'
app.config['SECRET_KEY'] = "Akshy Secret Message Noone should know"

db = SQLAlchemy(app)
migrate = Migrate(app, db)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True)
    favorite_color = db.Column(db.String(120))
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    password_hash = db.Column(db.String(200))

    @property
    def password(self):
        raise AttributeError("Password is not a readable attribute")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    # create a string

    def __repr__(self):
        return '<Name %r>' % self.name


class UserForm(FlaskForm):
    name = StringField("What's your Name?? ", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password_hash = PasswordField("Password", validators=[DataRequired(), EqualTo(
        'password_hash2', message='Passwords should match')])
    password_hash2 = PasswordField(
        "Confirm Password", validators=[DataRequired()])
    favorite_color = StringField("Favourite Color")
    submit = SubmitField("Submit")


class NameForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Submit")


class PasswordForm(FlaskForm):
    email = StringField("What is your Email", validators=[DataRequired()])
    password_hash = PasswordField("What is your Password",
                                  validators=[DataRequired()])
    submit = SubmitField("Submit")


@app.route("/")
def index():
    safe = "<b>safe</b>"
    capitalize = "capitalize"
    lower = "lower"
    upper = "upper"
    title = "title"
    trim = "trim  "
    striptags = "<b>striptags</b>"
    return render_template("index.html", safe1=safe, capitalize1=capitalize, lower1=lower, upper1=upper,
                           title1=title, trim1=trim, striptags1=striptags)


@app.route("/user/<name>")
def user(name):
    flavours = ["Vannila", "Strawberry", "ButterScotch"]
    return render_template("user.html", user_name=name, flavours=flavours)


@app.route("/name", methods=['GET', "POST"])
def name():
    name = None
    form = NameForm()
    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''
        flash("Form submitted Successfully")
    return render_template("name.html", name=name, form=form)


@app.route("/user/add", methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            hashed_pw = generate_password_hash(
                form.password_hash.data, "sha256")
            user = Users(name=form.name.data, email=form.email.data,
                         password_hash=hashed_pw,
                         favorite_color=form.favorite_color.data)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.email.data = ''
        form.favorite_color.data = ''
        form.password_hash.data = ''
        flash('User Created Successfully')
    our_users = Users.query.order_by(Users.date_added)
    return render_template('add_user.html', form=form, name=name, our_users=our_users)


@app.route("/update/<int:id>", methods=['GET', 'POST'])
def update(id):
    form = UserForm()
    name_to_update = Users.query.get_or_404(id)
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.favorite_color = request.form['favorite_color']
        try:
            db.session.commit()
            flash("User detail updated successfully")
            return render_template('update.html',
                                   form=form,
                                   name_to_update=name_to_update)
        except:
            flash("Error Something went wrong")
            return render_template('update.html',
                                   form=form,
                                   name_to_update=name_to_update)
    else:
        return render_template('update.html',
                               form=form,
                               name_to_update=name_to_update, id=id)


@app.route("/delete/<int:id>")
def delete(id):
    user_to_delete = Users.query.get_or_404(id)
    name = None
    form = UserForm()

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("User Deleted Successfully")
        our_users = Users.query.order_by(Users.date_added)
        return render_template('add_user.html', form=form, name=name, our_users=our_users)
    except:
        flash("aapudila yarume illaye pa")
        return render_template('add_user.html', form=form, name=name, our_users=our_users)


@app.route("/test_pw", methods=['GET', "POST"])
def test_pw():
    email = None
    password = None
    pw_to_check = None
    passed = None
    form = PasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password_hash.data
        form.email.data = ''
        form.password_hash.data = ''

        pw_to_check = Users.query.filter_by(email=email).first()
        # flash("Form submitted Successfully")
        passed = check_password_hash(pw_to_check.password_hash, password)
    return render_template("test_pw.html",  email=email, password=password, pw_to_check=pw_to_check, passed=passed, form=form)


@app.route("/date")
def get_current_date():
    return {"Date": date.today()}


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html"), 500
