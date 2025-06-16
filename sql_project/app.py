from config import sqlconfig, get_db_connection
from form import RegistrationForm, LoginForm 

import joblib
#   •	Used for XGboost Fishnet.
import bcrypt
# 	•	Used for hashing passwords securely.
import mysql.connector
# Connects the application to a MySQL database.
from flask import Flask, flash, redirect, render_template, request, session, url_for
""" 
	.   Flask: Initializes the Flask application.
	•	flash: Displays one-time messages to the user.
	•	redirect: Redirects the user to a different route.
	•	render_template: Renders HTML templates.
	•	request: Handles incoming request data (e.g., form submissions).
	•	session: Maintains session data for logged-in users.
	•	url_for: Generates URLs dynamically for routes.

"""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# Initialize the Flask application instance
app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

sqlconfig(app)

vectorizer = joblib.load("extras/xgboost_sqli_vectorizer.pkl")
model = joblib.load("extras/xgboost_sqli_model.pkl")


def tempered_query(query):
    vec = vectorizer.transform([query])
    pred = model.predict(vec)
    return pred[0] == 1
    
# Route for the homepage
@app.route("/")
def index():
    return render_template('index.html')

# Route for user registration
@app.route("/register", methods=['GET', 'POST'])
@limiter.limit("1/second")
def register():
    
    """ 
        Handles user registration:
	•	GET: Displays the registration form.
	•	POST: Processes the form submission, hashes the password, and stores user data in the database.
	•	Redirects to the login page upon success.
    """
    form = RegistrationForm()
    if form.validate_on_submit():  # Check if form submission is valid
        # Retrieve form data
        name = form.name.data
        email = form.email.data
        password = form.password.data

        # Hash the password using bcrypt for security
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        if any(tempered_query(field) for field in [email, name, password]):
            flash("Registration input rejected due to suspicious pattern.", "danger")
            return render_template("register.html", form=form)
        
        # Store user data in the database
        else:
            connection = get_db_connection()
            if connection:
                cursor = connection.cursor()
                cursor.execute(
                    "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
                    (name, email, hashed_password)
                )
                connection.commit()  # Commit the transaction
                cursor.close()
                connection.close()

            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))

    return render_template('register.html', form=form)

# Route for user login
@app.route("/login", methods=['GET', 'POST'])
@limiter.limit("1/second")
def login():
    """ 
    	Handles user login:
	•	Validates credentials against the database.
	•	Starts a session for the user upon successful login.
	•	Displays an error message if login fails.
    •	Displays an error message if login fails.
    """
    form = LoginForm()
    if form.validate_on_submit():  # Check if form submission is valid
        # Retrieve form data
        email = form.email.data
        password = form.password.data

        if any(tempered_query(field) for field in [email, password]):
            flash("login input rejected due to suspicious pattern.", "danger")
            return render_template("login.html", form=form)
        else:
            # Verify user credentials
            connection = get_db_connection()
            if connection:
                
                cursor = connection.cursor()
                
                # Creates a cursor object to interact with the database.
                # A cursor is used to execute SQL commands and fetch results from the database.
                # connection.cursor() establishes a session for executing queries.
                #The cursor acts as a pointer for operations within the database connection.
            
                cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
                
                # cursor.execute(...) sends the query to the database for execution.
                
                """ 
                "SELECT * FROM users WHERE email=%s" is a parameterized query.
                email=%s: The %s is a placeholder for a value to be securely passed to the query.
                (email,): A tuple containing the email value to substitute for %s.
                Parameterized queries prevent SQL injection attacks by ensuring input values are safely escaped.
                
                """
                
                user = cursor.fetchone()  # Fetch user data
                # Fetches the first row of the query result
                """ 
                cursor.fetchone() retrieves a single record (if it exists) that matches the query.
                The result is returned as a tuple:
                For example: ('John Doe', 'john@example.com', '<hashed_password>').
                If no record is found, None is returned.
                
                """
                
                cursor.close()
                # Closes the cursor to release resources.
                """ 
                After completing database operations, closing the cursor is a best practice to avoid memory or resource leaks.
                It ends the specific database session initiated by the cursor.
                
                """
                connection.close()
                # Closes the connection to the database.
                """ 
                Ensures that the database session is properly terminated.
                Avoids leaving open connections, which can exhaust database resources.
                
                """
                
                # Check if user exists and the password matches
                if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):  # user[3] is the hashed password
                    session['user_id'] = user[0]  # Assuming user[0] is the user ID
                    return redirect(url_for('dashboard'))
                else:
                    flash("Login failed. Please check your email and password", "danger")

    return render_template('login.html', form=form)

# Route for the user dashboard
@app.route("/dashboard")
def dashboard():
    """ 
        Displays the dashboard for logged-in users.
	•	Redirects to the login page if no user session exists.
    """
    if 'user_id' in session:  # Check if user is logged in
        user_id = session['user_id']

        # Retrieve user data from the database
        connection = get_db_connection()
        if connection:
            """ 
            Summary of Workflow
	        1.	Create a cursor to execute database commands.
	        2.	Use a parameterized SQL query to safely retrieve a user by their email.
	        3.	Fetch the user's data (if it exists) as a tuple.
	        4.	Close the cursor and connection to release resources.
            """
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
            user = cursor.fetchone()
            cursor.close()
            connection.close()

            if user:
                return render_template('dashboard.html', user=user)

    # Redirect to login if user is not authenticated
    return redirect(url_for('login'))

# Route for user logout
@app.route('/logout')
def logout():
    # Logs out the user by clearing the session and redirects to the login page.
    # Remove user from session
    session.pop('user_id', None)
    flash("You have been logged out successfully.", "success")
    return redirect(url_for('login'))

# Run the Flask application
if __name__ == "__main__":
    app.run(debug=True)