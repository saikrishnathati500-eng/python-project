
import os
import bcrypt

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, flash
from database import get_db_connection

load_dotenv()

app = Flask(__name__)

app.secret_key = os.environ["FLASK_SECRET_KEY"]


# GET request: Display registration page
@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


# POST request: Receive registration details
@app.route("/register", methods=["POST"])
def register():

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    if not username or not email or not password:
        flash("All fields are required.", "error")
        return redirect("/")

    if len(password.encode("utf-8")) > 72:
        flash("Password must not exceed 72 bytes.", "error")
        return redirect("/")

    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    conn = None
    cursor = None

    try:

        # Connect Python to PostgreSQL
        conn = get_db_connection()
        cursor = conn.cursor()

        # Insert user into database
        cursor.execute(
            """
            INSERT INTO users (username, email, password)
            VALUES (%s, %s, %s)
            """,
            (username, email, hashed_password)
        )

        conn.commit()

        flash("Registration successful!", "success")

    except Exception:
        if conn:
            conn.rollback()

        app.logger.exception("Registration failed")
        flash(
            "Registration failed. Check your database connection or email.",
            "error"
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()

    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
