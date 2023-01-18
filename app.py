from flask import Flask, render_template, session, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user

app = Flask(__name__)
app.secret_key = "Word_Counter_Key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost:5432/wordcount'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
with app.app_context():
    db = SQLAlchemy(app)
    db.create_all()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(10000))
    lifewordcount = db.Column(db.Integer)


loginmanager = LoginManager()
loginmanager.login_view = "loginpage"
loginmanager.init_app(app)


@loginmanager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template("home.html")


@app.route("/wordcollect", methods=["POST"])
@login_required
def wordcollect():
    text = request.form.get("content")
    session["new_words"] = len(text.split())
    session["words"] += session["new_words"]
    current_user.lifewordcount += session["new_words"]
    db.session.commit()
    return redirect(url_for("wordcount"))


@app.route('/wordcount')
@login_required
def wordcount():
    if "words" not in session:
        session["words"] = 0
        session["new_words"] = 0
    return render_template("wordcount.html", words=session["words"], new_words=session["new_words"],
                           lifewords=current_user.lifewordcount)


@app.route('/login', methods=["GET", "POST"])
def loginpage():
    return render_template("login.html")

@app.route('/logout', methods=["GET", "POST"])
def logoutpage():
    logout_user()
    return redirect(url_for("index"))

@app.route('/register', methods=["GET", "POST"])
def registerpage():
    return render_template("register.html")


@app.route('/submitregister', methods=["POST"])
def submitregister():
    un = request.form.get("username")
    pw = request.form.get("password1")
    pw2 = request.form.get("password2")

    user = User.query.filter_by(username=un).first()
    if user:
        flash('This username already exists.', category='error')
        return redirect(url_for("registerpage"))
    elif pw != pw2:
        flash('The passwords do not match.', category='error')
        return redirect(url_for("registerpage"))
    new_user = User(
        username=un, password=generate_password_hash(pw), lifewordcount=0)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for("loginpage"))


@app.route('/checklogin', methods=["POST"])
def checklogin():
    un = request.form.get("username")
    pw = request.form.get("password")
    user = User.query.filter_by(username=un).first()
    if not user:
        flash('This username does not exist.', category='error')
        return redirect(url_for("loginpage"))
    elif not check_password_hash(user.password, pw):
        flash('The password is incorrect.', category='error')
        return redirect(url_for("loginpage"))
    login_user(user)
    return redirect(url_for("wordcount"))


@app.route('/loginredirect', methods=["POST"])
def loginredirect():
    return redirect(url_for("loginpage"))


if __name__ == "__main__":
    app.run(debug=True)
