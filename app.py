import os

# import sqlite3 from cs50
from cs50 import SQL

from flask import Flask, flash, redirect, render_template, request, session
from functools import wraps
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
# import socket
import datetime

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Connect to the database and create a cursor
# conn = sqlite3.connect('projectManagement.db')
# db = conn.cursor()

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///projectManagement.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


@app.route("/login", methods=["GET", "POST"])
def login():
    """log in page"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Ensure username was submitted
        if not username:
            flash("Please enter your username.")
            return redirect("/login")

        # Ensure password was submitted
        elif not password:
            flash("Please enter your password.")
            return redirect("/login")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username exists and password is correct
        if len(rows) == 0:
            flash("Invalid username and/or password.")
            return redirect("/login")
        elif not check_password_hash(rows[0]["hash"], password):
            flash("Invalid username and/or password.")
            return redirect("/login")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """register page"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Ensure username was submitted
        if not username:
            flash("Please enter your username.")
            return redirect("/register")

        # Ensure password was submitted
        elif not password:
            flash("Please enter your password.")
            return redirect("/register")

        # Ensure confirmation password was submitted
        elif not request.form.get("confirmation"):
            flash("Please enter a confirmation password.")
            return redirect("/register")

        # Ensure that the confirmation password is correct
        elif request.form.get("confirmation") != request.form.get("password"):
            flash("passwords must match")
            return redirect("/register")

        # Ensure username is unique
        if len(db.execute("SELECT * FROM users WHERE username =?", username)) > 0:
            flash("Username already exists.")
            return redirect("/register")

        # Generate hash for password
        hashed_password = generate_password_hash(password)

        # Insert new user into database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                   username, hashed_password)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username =?", username)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change():
    """ Change Old Password """

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure old password was submitted
        if not request.form.get("old-password"):
            flash("must provide old password")
            return render_template("change-password.html")

        # Ensure new password was submitted
        elif not request.form.get("new-password"):
            flash("must provide new password")
            return render_template("change-password.html")

        # Ensure confirmation password was submitted
        elif not request.form.get("confirmation"):
            flash("must provide confirmation password")
            return render_template("change-password.html")

        # Ensure old password is correct
        get_hash = db.execute(
            "SELECT hash FROM users WHERE id = ?", session["user_id"])
        if not check_password_hash(get_hash[0]["hash"], request.form.get("old-password")):
            flash("old password is incorrect")
            return render_template("change-password.html")

        # Ensure that the confirmation password is correct
        elif request.form.get("old-password") == request.form.get("new-password"):
            flash("password must be new")
            return render_template("change-password.html")

        # Ensure that the confirmation password is correct
        elif request.form.get("confirmation") != request.form.get("new-password"):
            flash("passwords must match")
            return render_template("change-password.html")

        # Update the database with new password
        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(
            request.form.get("new-password")), session["user_id"])

        # Redirect user to home page and flash a message
        return redirect("/"), flash("Password Changed!")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("change-password.html")


@app.route("/")
@login_required
def index():
    projects = db.execute(
        "SELECT * FROM projects WHERE user_id = ?", session["user_id"])
    username = db.execute(
        "SELECT username FROM users WHERE id = ?", session["user_id"])
    name = username[0]['username']
    return render_template("index.html", username=name, projects=projects)


@app.route("/create-project", methods=["GET", "POST"])
@login_required
def create_project():
    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        team_members = request.form.get("team_members")

        # Insert project into the database
        db.execute(
            "INSERT INTO projects (user_id, title, description, team_members) VALUES (?, ?, ?, ?)",
            session["user_id"], title, description, team_members
        )

        flash("Project created successfully")
        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("create-project.html")


@app.route("/projects")
@login_required
def projects():
    projects = db.execute(
        "SELECT * FROM projects where user_id = (SELECT id FROM users WHERE id = ?)", session["user_id"])
    return render_template("projects.html", projects=projects)


@app.route("/tasks")
@login_required
def project_tasks():
    # Fetch tasks and title for the specified project from the database
    query = """
        SELECT task, title
        FROM projects
        JOIN tasks ON projects.id = tasks.project_id
        WHERE projects.user_id = :user_id
    """
    user_id = session["user_id"]
    tasks = db.execute(query, user_id=user_id)

    # Render the tasks template, passing the tasks as a parameter
    return render_template("tasks.html", tasks=tasks)


@app.route("/create-task", methods=["GET", "POST"])
@login_required
def create_task():
    if request.method == "POST":
        project_id = request.form.get("project")
        task = request.form.get("task")

        # Insert the task into the database
        db.execute("INSERT INTO tasks (user_id, project_id, task) VALUES (?, ?, ?)",
                   session["user_id"], project_id, task)

        flash("Task created successfully")

        # Redirect to the tasks page or wherever appropriate
        return redirect("/tasks")

    else:
        projects = db.execute(
            "SELECT * FROM projects WHERE user_id = ?", session["user_id"])
        return render_template("create-task.html", projects=projects)

# if __name__ == "__main__":
#     ip_address = socket.gethostbyname(socket.gethostname())
#     app.run(host=ip_address, port=8000)

# # Save changes and close connection
# conn.commit()
# conn.close()
