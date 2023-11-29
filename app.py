from flask import Flask, render_template, request, redirect, url_for, session, flash
from google.cloud import datastore, storage, secretmanager
import pyrebase
import jwt
import requests
import logging
import json
import os
from google.api_core.exceptions import FailedPrecondition
from datetime import datetime, timedelta

# Initialize logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Create a Secret Manager client
secret_client = secretmanager.SecretManagerServiceClient()

# Function to access a secret
def access_secret(secret_name):
    project_id = "project_id" 
    name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
    response = secret_client.access_secret_version(request={"name": name})
    return response.payload.data.decode('UTF-8')

# Fetch and set secrets
app.secret_key = access_secret('SECRET_KEY')
gcp_key_json_str = access_secret('GCP_KEY_JSON')
firebase_config_json = access_secret('FIREBASE_CONFIG')


# Firebase configuration
firebaseConfig = json.loads(firebase_config_json)
firebase = pyrebase.initialize_app(firebaseConfig)
auth = firebase.auth()

# Specify the name of your Google Cloud Storage bucket
bucket_name = 'bucket_name'
project_id = 'project_id'

# Google Cloud Storage and Datastore clients
storage_client = storage.Client()
datastore_client = datastore.Client()

# Function to log and flash errors
def log_and_flash_error(error_message):
    flash(f'Error: {error_message}', 'danger')
    logger.error('Error: %s', error_message)

# Helper function to get user ID from the session
def get_user_id():

    if 'user' in session:
        user_id_token = jwt.decode(session['user'], app.secret_key, algorithms=['HS256'])['user_id_token']
        return auth.get_account_info(user_id_token)['users'][0]['localId']
    return None

def create_image_entity(user_id, blob_name, blob_size, blob_url):
    client = datastore.Client()
    key = client.key('UserImage')  # 'userImage' is the new kind name
    entity = datastore.Entity(key=key)

    entity.update({
    'user_id': user_id,
    'blob_name': blob_name,
    'blob_size': blob_size,
    'blob_url': blob_url,
    'created_at': datetime.utcnow()
})


    client.put(entity)

@app.route('/')
def index():
     
    logger.info('Received index request')

    error_message = session.pop('error_message', None)

    if 'user' in session:
        return render_template('index.html')
    else:
        return render_template('signup.html', error_message=error_message)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error_message = None

    if request.method == 'POST':
        logger.info('Received signup request')
        email = request.form['email']
        password = request.form['password']

        try:
            if len(password) < 6:
                # Password is less than 6 characters
                error_message = 'Password must be at least 6 characters long.'
            else:
                logger.info('Creating a new user with email: %s', email)
                user = auth.create_user_with_email_and_password(email, password)
                logger.info('User created successfully')
                session['user_email'] = email  
                user_id_token = user['idToken']
                session_cookie = jwt.encode({'user_id_token': user_id_token}, app.secret_key, algorithm='HS256')
                session['user'] = session_cookie

                flash('Signup successful!', 'success')
                logger.info('Redirecting to index after successful signup')
                return redirect(url_for('index'))

        except requests.exceptions.HTTPError as e:
            error_data = getattr(e, 'response', None)
            if error_data is not None:
                try:
                    error_message = error_data.json().get('error', {}).get('message', 'An unknown error occurred')
                    if 'email' in error_message.lower() and 'exists' in error_message.lower():
                        # Specific error for existing email
                        error_message = 'Email already exists. Please use a different email.'
                except ValueError:
                    error_message = 'An unknown error occurred'
                
                # Print the full exception details for debugging
                logger.error('Exception details: %s', e)
            else:
                # Set a generic error message for the user
                if not error_message:
                    error_message = 'Signup failed. Please check your email and password.'

            flash(error_message, 'danger')
            logger.error('Signup failed: %s', error_message)

        except Exception as e:
            flash(f'Signup failed: {str(e)}', 'danger')
            logger.error('Signup failed: %s', str(e))

    return render_template('signup.html', error_message=error_message)




@app.route('/login', methods=['GET', 'POST'])
def login():
    error_message = None

    if request.method == 'POST':
        logger.info('Received login request')
        email = request.form['email']
        password = request.form['password']

        try:
            logger.info('Attempting to sign in user with email: %s', email)
            user = auth.sign_in_with_email_and_password(email, password)
            logger.info('User signed in successfully')
            session['user_email'] = email 

            user_id_token = user['idToken']
            session_cookie = jwt.encode({'user_id_token': user_id_token}, app.secret_key, algorithm='HS256')
            session['user'] = session_cookie
              # Replace this with your actual login success condition
            flash('Login successful!', 'success')
            logger.info('Redirecting to index after successful login')
            return redirect(url_for('index'))

        except requests.exceptions.HTTPError as e:
            error_data = getattr(e, 'response', None)
            if error_data is not None:
                try:
                    error_message = error_data.json().get('error', {}).get('message', 'An unknown error occurred')
                except ValueError:
                    error_message = 'An unknown error occurred'
                
                # Print the full exception details for debugging
                logger.error('Exception details: %s', e)
            else:
                # Set a generic error message for the user
                error_message = 'Login failed. Please check your email and password.'

            # Pass the specific Firebase error message to the template
            flash(error_message, 'danger')
            logger.error('Login failed: %s', error_message)

    return render_template('login.html', error_message=error_message)


@app.route('/list')
def list_files():
    if 'user' not in session:
        return redirect(url_for('login'))

    user_id = get_user_id()
    if not user_id:
        return redirect(url_for('login'))

    bucket = storage_client.bucket(bucket_name)
    prefix = f"{user_id}_"  # Prefix to filter files for the logged-in user
    blobs = bucket.list_blobs(prefix=prefix)

    # Create a list to store file information, including metadata and image URLs
    file_info_list = []

    for blob in blobs:
        # Only include files uploaded by the user
        if blob.name.startswith(prefix):
            blob_metadata = {
                'name': blob.name[len(prefix):],  # Remove the user_id prefix from the displayed name
                'content_type': blob.content_type,
                'size': blob.size,
                'updated': blob.updated,
            }

            # Generate a signed URL for the blob
            blob_url = blob.public_url

            file_info_list.append({
                'metadata': blob_metadata,
                'image_url': blob_url,
            })

    return render_template('list.html', file_info_list=file_info_list)

    
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    user_id = get_user_id()
    if not user_id:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files.get('file')
        if file and file.filename:
            unique_filename = f"{user_id}_{file.filename}"
            blob = storage_client.bucket(bucket_name).blob(unique_filename)
            blob.upload_from_file(file)

            create_image_entity(user_id, unique_filename, file.content_length,
                                f'https://storage.cloud.google.com/{bucket_name}/{unique_filename}')

            flash(f"File '{file.filename}' uploaded successfully!", 'success')

            # Redirect to the /list route after successful upload
            return redirect(url_for('list_files'))

        else:
            flash("No file selected for upload", 'error')

    return render_template('upload.html')


@app.route('/download/<filename>')
def download_file(filename):
    user_id = get_user_id()
    if not user_id:
        return redirect(url_for('login'))

    blob = storage_client.bucket(bucket_name).blob(f"{user_id}_{filename}")
    if blob.exists():
        return redirect(blob.public_url)
    else:
        flash("File not found", 'error')
        return redirect(url_for('list_files'))

@app.route('/delete/<filename>')
def delete_file(filename):
    user_id = get_user_id()
    if not user_id:
        return redirect(url_for('login'))

    full_filename = f"{user_id}_{filename}"
    blob = storage_client.bucket(bucket_name).blob(full_filename)
    
    # Delete the file from the Google Cloud Storage bucket
    if blob.exists():
        blob.delete()
        flash(f"File '{filename}' deleted successfully from storage.", 'success')
    else:
        flash("File not found in storage.", 'error')
        return redirect(url_for('list_files'))

    # Delete the corresponding entity from Google Cloud Datastore
    try:
        query = datastore_client.query(kind='UserImage')
        query = query.add_filter('property', '=', 'blob_name', value=full_filename) 
        results = list(query.fetch())

        if results:
            for entity in results:
                datastore_client.delete(entity.key)
            flash(f"Metadata for '{filename}' deleted successfully.", 'success')
        else:
            logger.error(f"No metadata found for file: {full_filename}")
            flash(f"No metadata found for '{filename}'.", 'error')
    except Exception as e:
        logger.error(f"Error deleting metadata for file: {full_filename}")       
    return redirect(url_for('list_files'))


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if 'user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        session.pop('user', None)
        flash('You have been logged out.', 'info')  # Optional: Show a logout message
        return redirect(url_for('login'))
    else:
        # Handle GET requests (if needed)
        return render_template('login.html') 


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)