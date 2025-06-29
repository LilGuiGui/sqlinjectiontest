from config import sqlconfig, get_db_connection
from form import RegistrationForm, LoginForm 

import joblib
#   •   Used for XGboost Fishnet.
import bcrypt
#   •   Used for hashing passwords securely.
import mysql.connector
# Connects the application to a MySQL database.
from flask import Flask, flash, redirect, render_template, request, session, url_for, jsonify
""" 
    .   Flask: Initializes the Flask application.
    •   flash: Displays one-time messages to the user.
    •   redirect: Redirects the user to a different route.
    •   render_template: Renders HTML templates.
    •   request: Handles incoming request data (e.g., form submissions).
    •   session: Maintains session data for logged-in users.
    •   url_for: Generates URLs dynamically for routes.

"""
from flask_principal import Principal, Permission, RoleNeed, identity_changed, Identity, AnonymousIdentity, identity_loaded, UserNeed
"""
    •   ADDED ON V2, Role Implementation in which DEFAULT is always user (handled by SQLDefault), and administrator role is modified SOLELY 
        by SQL Commands, Flask or any SHOULD NOT modify or handle agent role, basically, paranoid of attacks that alleviate Role through Client
    •   Principal: Handles User Role
        admin : has the right to View, Delete, but never edit, that is against integrity of a Data (CIA TRIAD)
        users : NPC ahh 
"""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize the Flask application instance
app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["20000 per day", "1000 per hour"],
    storage_uri="memory://",
)

sqlconfig(app)

# copied from pythonhoster.org
principal = Principal(app)
admin_permission = Permission(RoleNeed('administrator'))
user_permission = Permission(RoleNeed('user'))

vectorizer = joblib.load("extras/xgboost_sqli_vectorizer.pkl")
model = joblib.load("extras/xgboost_sqli_model.pkl")

def tempered_query(query):
    vec = vectorizer.transform([query])
    pred = model.predict(vec)
    return pred[0] == 1

# FIX 1: Add the missing get_user_role function
def get_user_role(user_id):
    """Get the role of a user by their ID"""
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        cursor.execute("SELECT role FROM users WHERE id=%s", (user_id,))
        result = cursor.fetchone()
        cursor.close()
        connection.close()
        
        if result:
            return result[0]
    return None

@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    identity.user = session.get('user_id')
    
    if hasattr(identity, 'user') and identity.user:
        identity.provides.add(UserNeed(identity.user))
        
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            cursor.execute("SELECT role FROM users WHERE id=%s", (identity.user,))
            user_role = cursor.fetchone()
            cursor.close()
            connection.close()
            
            if user_role and user_role[0]:
                identity.provides.add(RoleNeed(user_role[0]))

# Route for the homepage
@app.route("/")
def index():
    return render_template('index.html')

# Route for user registration
@app.route("/register", methods=['GET', 'POST'])
@limiter.limit("100/second")
def register():
    
    """ 
        Handles user registration:
    •   GET: Displays the registration form.
    •   POST: Processes the form submission, hashes the password, and stores user data in the database.
    •   Redirects to the login page upon success.
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
                connection.commit()  
                cursor.close()
                connection.close()

            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))

    return render_template('register.html', form=form)

# Route for user login
@app.route("/login", methods=['GET', 'POST'])
@limiter.limit("100/second")
def login():
    """ 
        Handles user login:
    •   Validates credentials against the database.
    •   Starts a session for the user upon successful login.
    •   Displays an error message if login fails.
    •   Displays an error message if login fails.
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
                    identity_changed.send(app, identity=Identity(user[0])) #loaded
                    return redirect(url_for('dashboard'))
                else:
                    flash("Login failed. Please check your email and password", "danger")

    return render_template('login.html', form=form)

# Route for the user dashboard
@app.route("/dashboard")

# After a bit of Research, apparently this decorator and Func below effectibely provide added negligible security
# value but im a paranoid and dumb asl, Principal is Deprecated.
def dashboard():
    """ 
        Workflow:
        1. Displays the dashboard for logged-in regular users only.
        2. Admins are redirected to their own dashboard.
    """
    if 'user_id' in session:  # Check if user is logged in
        user_id = session['user_id']
        
        user_role = get_user_role(user_id)
        if user_role == 'administrator':
            return redirect(url_for('admin_dashboard'))

        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
            user = cursor.fetchone()
            cursor.close()
            connection.close()

            if user:
                return render_template('dashboard.html', user=user)

    return redirect(url_for('login'))

@app.route("/admin-dashboard")
@admin_permission.require()
def admin_dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            
            cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
            admin_user = cursor.fetchone()
            
            cursor.execute("SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC")
            all_users = cursor.fetchall()
            
            cursor.close()
            connection.close()
            
            if admin_user:
                return render_template('admin_dashboard.html', 
                                     user=admin_user, 
                                     users=all_users)
    
    return redirect(url_for('login'))

@app.route("/admin/delete_user/<int:user_id>", methods=['POST'])
@admin_permission.require(http_exception=403)
def delete_user(user_id):
    if user_id == session.get('user_id'):
        flash("You Cannot Delete Your Own Account","danger")
        return redirect(url_for('admin_dashboard'))  
    else:
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            
            cursor.execute("SELECT name FROM users WHERE id=%s", (user_id,))
            user_to_delete = cursor.fetchone()
            
            if user_to_delete:
                cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
                connection.commit()
                affected_rows = cursor.rowcount
                
                cursor.close()
                connection.close()
                
                if affected_rows > 0:
                    flash(f"User '{user_to_delete[0]}' has been deleted successfully.", "success")
                else:
                    flash(f"ERROR! User '{user_to_delete[0]}' was not deleted!", "danger") 
            else:
                cursor.close()
                connection.close()
                flash("ERROR! User not found", "danger") 
        else:
            flash("Database connection failed", "danger")  
        
        return redirect(url_for('admin_dashboard'))  

# Route for user logout
@app.route('/logout')
def logout():
    # Logs out the user by clearing the session and redirects to the login page.
    # Remove user from session
    session.pop('user_id', None)
    identity_changed.send(app, identity=AnonymousIdentity())
    flash("You have been logged out successfully.", "success")
    return redirect(url_for('login'))

# Run the Flask application
if __name__ == "__main__":
    app.run(host="0.0.0.0",port=5000,debug=True)
    print(app.url_map)
