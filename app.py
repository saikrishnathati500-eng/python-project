
from flask import Flask, render_template, request, redirect, flash
from database import get_db_connection
import bcrypt
import os

app = Flask(__name__)

app.secret_key = os.environ["FLASK_SECRET_KEY"]


@app.route("/", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]

        if not username or not email or not password:
            flash("All fields are required!")
            return redirect("/")

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        db = None
        cursor = None

        try:
            db = get_db_connection()
            cursor = db.cursor()

            query = """
                INSERT INTO users (username, email, password)
                VALUES (%s, %s, %s)
            """

            cursor.execute(
                query,
                (username, email, hashed_password)
            )

            db.commit()

            flash("Registration successful!")

        except Exception as error:

            if db:
                db.rollback()

            print("Database error:", error)
            flash("Registration failed!")

        finally:

            if cursor:
                cursor.close()

            if db:
                db.close()

        return redirect("/")

    return render_template("index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
