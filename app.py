from flask import *
import pymysql
import json
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

from forms import LoginForm, AdminForm, CategoryForm,RegisterAdminForm
import os
import secrets

app.secret_key = secrets.token_hex(16)





def get_database_connection():
    return pymysql.connect(
        host='localhost',
        user='root',
        password='',
        database='shopDB'
    )





@app.route('/admin', methods=['GET', 'POST'])
def admin():
    print(session)

    # check if the logged-in admin has the super admin privileges
    if 'logged_in' in session and 'super_admin' in session['privileges'] and session['privileges']['super_admin']:
        connection = get_database_connection()
        cursor = connection.cursor(pymysql.cursors.DictCursor)
        
        if request.method == 'POST':
            action = request.form['action']
            if action == 'add_role':
                role_name = request.form['role_name']
                privileges = request.form.getlist('privileges')
                cursor.execute('INSERT INTO roles (name, privileges) VALUES (%s, %s)', (role_name, json.dumps({privilege: True for privilege in privileges})))
                connection.commit()
            elif action == 'assign_role':
                admin_username = request.form['admin_username']
                role_id = request.form['role_id']
                cursor.execute('UPDATE admins SET role_id = %s WHERE username = %s', (role_id, admin_username))
                connection.commit()
            elif action == 'deassign_role':
                admin_username = request.form['admin_username']
                cursor.execute('UPDATE admins SET role_id = NULL WHERE username = %s', (admin_username))
                connection.commit()
        
        cursor.execute('SELECT * FROM admins')
        admins = cursor.fetchall()
        cursor.execute('SELECT * FROM roles')
        roles = cursor.fetchall()
        connection.close()
        
        return render_template('admin.html', admins=admins, roles=roles)
    else:
        return redirect(url_for('login'))


@app.route('/add_admin', methods=['GET', 'POST'])
def add_admin():
    connection = get_database_connection()
    cursor = connection.cursor(pymysql.cursors.DictCursor)
    if 'logged_in' in session and 'add_admins' in session['privileges'] and session['privileges']['add_admins']:
        form = AdminForm()
        if form.validate_on_submit():
            username = form.username.data
            hashed_password = generate_password_hash(form.password.data, method='sha256')
            role_id = form.role_id.data  # you'll need a dropdown in your form to select roles
            
            cursor.execute('INSERT INTO admins (username, password, role_id) VALUES (%s, %s, %s)', (username, hashed_password, role_id))
            # Commit changes to the database (if using something like Flask-SQLAlchemy)
            connection.commit()
            
            flash('Admin added successfully!', 'success')
            return redirect(url_for('add_admin'))
        return render_template('add_admin.html', form=form)
    else:
        return redirect(url_for('login'))


@app.route('/manage_categories', methods=['GET', 'POST'])
def manage_categories():
    connection = get_database_connection()
    cursor = connection.cursor(pymysql.cursors.DictCursor)
    if 'logged_in' in session and 'manage_categories' in session['privileges'] and session['privileges']['manage_categories']:
        form = CategoryForm()
        if form.validate_on_submit():
            category_name = form.name.data
            
            # Add the category to the database
            cursor.execute('INSERT INTO categories (name) VALUES (%s)', (category_name,))
            # Commit changes to the database (if using something like Flask-SQLAlchemy)
            connection.commit()


            flash('Category added successfully!', 'success')
            return redirect(url_for('manage_categories'))
        return render_template('manage_categories.html', form=form)
    else:
        return redirect(url_for('login'))


@app.route('/customer_support')
def customer_support():
    connection = get_database_connection()
    cursor = connection.cursor(pymysql.cursors.DictCursor)
    if 'logged_in' in session and 'customer_support' in session['privileges'] and session['privileges']['customer_support']:
        # Fetch inquiries from the database
        cursor.execute('SELECT * FROM inquiries')
        inquiries = cursor.fetchall()
        return render_template('customer_support.html', inquiries=inquiries)
    else:
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    connection = get_database_connection()
    cursor = connection.cursor(pymysql.cursors.DictCursor)
    form = LoginForm()
    
    if request.method == 'POST':
        print("POST request detected.")  # This will help determine if the form is submitting
        
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            
            print("Attempting to log in user:", username)
            cursor.execute('SELECT * FROM admins WHERE username = %s', (username))
            admin = cursor.fetchone()

            if admin:
                print("User found in database.")
            else:
                print("User not found.")
                
            if admin and check_password_hash(admin['password'], password):
                print("Password is correct.")
                
                if not admin['role_id']:
                    print("Admin does not have a role assigned.")
                    flash('Your account does not have an assigned role. Please contact the super admin.', 'warning')
                    return redirect(url_for('login'))

                session['logged_in'] = True
                cursor.execute('SELECT privileges FROM roles WHERE id = %s', (admin['role_id']))
                role = cursor.fetchone()
                session['privileges'] = json.loads(role['privileges'])
                return redirect(determine_redirect_url(session['privileges']))
            
            else:
                print("Password check failed.")
                flash('Invalid username or password', 'danger')
        else:
            print("Form validation failed.")
            for field, errors in form.errors.items():
                for error in errors:
                    print(f"Error in {field}: {error}")

    return render_template('login.html', form=form)


def determine_redirect_url(privileges):
    # Define priority of redirects based on the privilege importance.
    # You can customize this order based on your needs.
    redirect_order = [
        ('super_admin', url_for('admin')),
        ('add_admins', url_for('add_admin')),
        ('manage_categories', url_for('manage_categories')),
        ('customer_support', url_for('customer_support')),
    ]
    
    for privilege, url in redirect_order:
        if privilege in privileges and privileges[privilege]:
            return url

    # Default redirect if none of the above privileges match
    return url_for('login')



@app.route('/register_admin', methods=['GET', 'POST'])
def register_admin():
    connection = get_database_connection()
    cursor = connection.cursor(pymysql.cursors.DictCursor)
    form = RegisterAdminForm()
    


    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        username = form.username.data
        

        # Add the new admin to the 'admins' table
        cursor.execute('INSERT INTO admins (username, password) VALUES (%s, %s)', (username, hashed_password))
        # Remember to commit changes if needed
        connection.commit()

        flash('Admin registered successfully!', 'success')
        return redirect(url_for('admin'))
    else: # This else is executed when the form is submitted but not valid
        for fieldName, errorMessages in form.errors.items():
            for err in errorMessages:
                flash(f"Error in {fieldName}: {err}", 'danger')
    return render_template('register_admin.html', form=form)


@app.route('/add_role', methods=['POST'])
def add_role():
    role_name = request.form.get('role_name')
    
    # The form gives "privileges" as a list of checked values
    privileges_list = request.form.getlist('privileges')
    
    # Convert the list into a dictionary with boolean values
    privileges_dict = {privilege: True for privilege in privileges_list}
    
    # Convert the dictionary to a JSON string for storage in your database
    privileges_json = json.dumps(privileges_dict)

    # Insert this role into your roles table
    connection = get_database_connection()
    cursor = connection.cursor(pymysql.cursors.DictCursor)
    cursor.execute('INSERT INTO roles (name, privileges) VALUES (%s, %s)', (role_name, privileges_json))
    connection.commit()

    flash('Role added successfully!', 'success')
    return redirect(url_for('admin'))



@app.route('/assign_role', methods=['POST'])
def assign_role():
    admin_username = request.form.get('admin_username')
    role_id = request.form.get('role_id')

    # Fetch the admin with the given username
    connection = get_database_connection()
    cursor = connection.cursor(pymysql.cursors.DictCursor)
    cursor.execute('UPDATE admins SET role_id = %s WHERE username = %s', (role_id, admin_username))
    connection.commit()

    flash('Role assigned successfully!', 'success')
    return redirect(url_for('admin'))



@app.route('/deassign_role', methods=['POST'])
def deassign_role():
    admin_username = request.form.get('admin_username')

    # Deassign the role for the given admin
    connection = get_database_connection()
    cursor = connection.cursor(pymysql.cursors.DictCursor)
    cursor.execute('UPDATE admins SET role_id = NULL WHERE username = %s', (admin_username,))
    connection.commit()

    flash('Role deassigned successfully!', 'success')
    return redirect(url_for('admin'))


if __name__ == '__main__':
    app.run(debug=True)


