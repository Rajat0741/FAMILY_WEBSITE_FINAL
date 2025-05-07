from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory, Response, stream_with_context
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user, AnonymousUserMixin
import os
from datetime import datetime, timedelta
from functools import wraps, lru_cache
import json
import uuid
from werkzeug.utils import secure_filename
import tempfile
from PIL import Image, ImageDraw
from io import BytesIO
import time
from googleapiclient.http import MediaIoBaseDownload, MediaFileUpload
import ssl
import mimetypes

# Import the Google Drive service
from gdrive import GoogleDriveService

app = Flask(__name__, 
    template_folder='templates',
    static_folder='static'
)
app.secret_key = os.environ.get('SECRET_KEY', 'from environment var')  # Use environment variable in production
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=int(os.environ.get('SESSION_TIMEOUT', '120')))  # Session timeout
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', '/tmp/uploads' if os.path.exists('/tmp/uploads') else tempfile.gettempdir())  # Temporary folder for uploads
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_UPLOAD_SIZE', 10 * 1024 * 1024 * 1024))  # Upload size limit

# Application settings
MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', '5'))
BLOCK_DURATION_HOURS = int(os.environ.get('BLOCK_DURATION_HOURS', '48'))

# Upload progress tracking
upload_progress = {}
# Store resumable upload URIs
resumable_uploads = {}

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Store for blocked IPs - in production this should be in a database
blocked_ips = {}
failed_attempts = {}

# Default passwords - In production, these should be from environment variables
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', "admin123")
MEMBER_PASSWORD = os.environ.get('MEMBER_PASSWORD', "family123")

# File types that are allowed to be uploaded
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi'}

# In-memory cache for thumbnails with metadata
MAX_CACHE_SIZE = int(os.environ.get('MAX_CACHE_SIZE', '100'))  # Smaller in production to conserve memory
CACHE_EXPIRY = int(os.environ.get('CACHE_EXPIRY', '3600'))  # Cache expiry in seconds (1 hour)
MAX_API_RETRIES = int(os.environ.get('MAX_API_RETRIES', '3'))  # Maximum retries for API calls
thumbnail_cache = {}

# Add a singleton pattern for the drive service to maintain a single connection
_drive_service_instance = None

def get_drive_service():
    global _drive_service_instance
    if _drive_service_instance is None or not _drive_service_instance.service:
        _drive_service_instance = GoogleDriveService()
    return _drive_service_instance

# Initialize Google Drive service
drive_service = get_drive_service()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, role):
        self.id = id
        self.role = role

# Anonymous user for handling not authenticated users
class Anonymous(AnonymousUserMixin):
    @property
    def role(self):
        return 'anonymous'

login_manager.anonymous_user = Anonymous

# Mock user database - In production, use a real database
users = {
    'admin': {'password': ADMIN_PASSWORD, 'role': 'admin'},
    'member': {'password': MEMBER_PASSWORD, 'role': 'member'}
}

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id, users[user_id]['role'])
    return None

# Custom decorator for admin-only routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.role == 'admin':
            return f(*args, **kwargs)
        flash('You need admin privileges to access this page.', 'danger')
        return redirect(url_for('gallery'))
    return decorated_function

# Check if IP is blocked
def is_ip_blocked(ip):
    if ip in blocked_ips:
        block_time = blocked_ips[ip]
        if datetime.now() < block_time:
            # Still blocked
            remaining = block_time - datetime.now()
            return True, int(remaining.total_seconds() // 3600)
        else:
            # Block expired
            del blocked_ips[ip]
            if ip in failed_attempts:
                del failed_attempts[ip]
    return False, 0

# Check if file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Helper function to get folder breadcrumbs
def get_breadcrumbs(folder_id):
    breadcrumbs = []
    current_id = folder_id
    
    # Start with the root folder if not already specified
    if folder_id != 'root':
        # Get the root folder
        root_folder_id = drive_service.root_folder_id
        if not root_folder_id:
            root_folder_id = drive_service.ensure_root_folder()
        
        # Add root folder to breadcrumbs
        breadcrumbs.append({
            'id': root_folder_id,
            'name': 'Main Folder'
        })
        
        # Get path to current folder
        while current_id and current_id != root_folder_id:
            # Get folder metadata
            folder_metadata = drive_service.get_file_metadata(current_id)
            if folder_metadata:
                breadcrumbs.append({
                    'id': current_id,
                    'name': folder_metadata['name']
                })
                
                # Try to get parent from the metadata
                # Note: This might require additional API calls with proper fields
                # For simplicity, we'll get the parent folder directly
                parent_id = None
                # In a real implementation, we would traverse up to find the parent
                # For now, we'll stop the loop
                break
            else:
                break
    else:
        # Just add the root folder
        breadcrumbs.append({
            'id': 'root',
            'name': 'Main Folder'
        })
    
    return breadcrumbs

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    
    if request.method == 'POST':
        # Get the client's IP address
        ip = request.remote_addr
        
        # Check if IP is blocked
        blocked, hours = is_ip_blocked(ip)
        if blocked:
            return render_template('login.html', 
                                  error=f"Your IP has been blocked for {hours} more hours due to too many failed attempts.")
        
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in users and users[username]['password'] == password:
            # Successful login
            user = User(username, users[username]['role'])
            login_user(user)
            
            # Reset failed attempts for this IP
            if ip in failed_attempts:
                del failed_attempts[ip]
                
            flash(f'Welcome, {username}!', 'success')
            return redirect(url_for('gallery'))
        else:
            # Failed login attempt
            if ip not in failed_attempts:
                failed_attempts[ip] = 1
            else:
                failed_attempts[ip] += 1
                
            # Block IP after MAX_LOGIN_ATTEMPTS failed attempts
            if failed_attempts[ip] >= MAX_LOGIN_ATTEMPTS:
                block_time = datetime.now() + timedelta(hours=BLOCK_DURATION_HOURS)
                blocked_ips[ip] = block_time
                return render_template('login.html', 
                                      error=f"Too many failed login attempts. Your IP has been blocked for {BLOCK_DURATION_HOURS} hours.")
            
            remaining_attempts = MAX_LOGIN_ATTEMPTS - failed_attempts[ip]
            error = f"Invalid username or password. {remaining_attempts} attempts remaining before your IP is blocked."
    
    return render_template('login.html', error=error)

@app.route('/gallery')
@app.route('/gallery/<folder_id>')
@login_required
def gallery(folder_id=None):
    # Ensure drive service is authenticated
    if not drive_service.service:
        if not drive_service.authenticate():
            flash('Could not authenticate with Google Drive. Please check your credentials.', 'danger')
            return render_template('gallery.html', 
                                  is_admin=(current_user.role == 'admin'),
                                  current_folder={'name': 'Main Folder'},
                                  folder_id='root',
                                  breadcrumbs=[{'id': 'root', 'name': 'Main Folder'}],
                                  subfolders={},
                                  media={})
    
    # Ensure we have a root folder
    if not folder_id:
        folder_id = drive_service.root_folder_id
        if not folder_id:
            folder_id = drive_service.ensure_root_folder()
    
    # Get folder contents
    try:
        is_admin = current_user.role == 'admin'
        files = drive_service.get_folder_contents(folder_id)
        
        # Separate folders and media
        subfolders = {}
        media = {}
        
        for file in files:
            file_id = file['id']
            if file['mimeType'] == 'application/vnd.google-apps.folder':
                # It's a folder
                subfolders[file_id] = {
                    'name': file['name'],
                    'created_at': file['createdTime']
                }
            else:
                # It's a media file
                media_type = 'video' if 'video' in file['mimeType'] else 'image'
                media[file_id] = {
                    'name': file['name'],
                    'type': media_type,
                    'uploaded_at': file['createdTime']
                }
        
        # Get current folder details
        if folder_id == drive_service.root_folder_id or folder_id == 'root':
            current_folder = {'name': 'Main Folder'}
        else:
            folder_metadata = drive_service.get_file_metadata(folder_id)
            current_folder = {'name': folder_metadata['name']} if folder_metadata else {'name': 'Unknown Folder'}
        
        # Get breadcrumbs
        breadcrumbs = get_breadcrumbs(folder_id)
        
        return render_template('gallery.html', 
                              is_admin=is_admin,
                              current_folder=current_folder,
                              folder_id=folder_id,
                              breadcrumbs=breadcrumbs,
                              subfolders=subfolders,
                              media=media)
    except Exception as e:
        flash(f'Error fetching folder contents: {str(e)}', 'danger')
        return redirect(url_for('gallery'))

@app.route('/folder/create', methods=['POST'])
@login_required
def create_folder():
    folder_name = request.form.get('folder_name')
    parent_id = request.form.get('parent_id', None)
    
    # Validate inputs
    if not folder_name or folder_name.strip() == '':
        flash('Please enter a folder name.', 'danger')
        return redirect(url_for('gallery', folder_id=parent_id))
    
    # Ensure drive service is authenticated
    if not drive_service.service:
        if not drive_service.authenticate():
            flash('Could not authenticate with Google Drive. Please check your credentials.', 'danger')
            return redirect(url_for('gallery', folder_id=parent_id))
    
    # Create folder in Google Drive
    try:
        folder_id = drive_service.create_folder(folder_name, parent_id)
        if folder_id:
            flash(f'Folder "{folder_name}" created successfully.', 'success')
        else:
            flash('Failed to create folder.', 'danger')
    except Exception as e:
        flash(f'Error creating folder: {str(e)}', 'danger')
    
    return redirect(url_for('gallery', folder_id=parent_id))

@app.route('/folder/delete/<folder_id>', methods=['POST'])
@login_required
@admin_required
def delete_folder(folder_id):
    if folder_id == drive_service.root_folder_id or folder_id == 'root':
        flash('Cannot delete the root folder.', 'danger')
        return redirect(url_for('gallery'))
    
    # Ensure drive service is authenticated
    if not drive_service.service:
        if not drive_service.authenticate():
            flash('Could not authenticate with Google Drive. Please check your credentials.', 'danger')
            return redirect(url_for('gallery'))
    
    try:
        # Get parent folder ID before deleting
        folder_metadata = drive_service.get_file_metadata(folder_id)
        if not folder_metadata:
            flash('Folder not found.', 'danger')
            return redirect(url_for('gallery'))
        
        # Get folder contents to check if it's empty
        contents = drive_service.get_folder_contents(folder_id)
        if contents:
            flash('Cannot delete folder with contents. Empty the folder first.', 'danger')
            return redirect(url_for('gallery', folder_id=folder_id))
        
        # Delete folder
        if drive_service.delete_file_or_folder(folder_id):
            flash(f'Folder "{folder_metadata["name"]}" deleted successfully.', 'success')
            # For simplicity, redirect to root folder after deletion
            # In a more advanced implementation, we could redirect to the parent folder
            return redirect(url_for('gallery'))
        else:
            flash('Failed to delete folder.', 'danger')
            return redirect(url_for('gallery', folder_id=folder_id))
    except Exception as e:
        flash(f'Error deleting folder: {str(e)}', 'danger')
        return redirect(url_for('gallery'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    # Check if upload directory is writable
    if not ensure_upload_dir():
        flash('Server storage is not available. Please try again later.', 'danger')
        return redirect(request.referrer or url_for('gallery'))
    
    # Check if the post request has the file part
    if 'mediaFile' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.referrer or url_for('gallery'))
    
    folder_id = request.form.get('folder_id')
    files = request.files.getlist('mediaFile')
    
    if not files or files[0].filename == '':
        flash('No selected file', 'danger')
        return redirect(request.referrer or url_for('gallery', folder_id=folder_id))
    
    # Ensure drive service is authenticated
    if not drive_service.service:
        if not drive_service.authenticate():
            flash('Could not authenticate with Google Drive. Please check your credentials.', 'danger')
            return redirect(url_for('gallery', folder_id=folder_id))
    
    uploaded_count = 0
    error_count = 0
    
    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            
            # Save file temporarily
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(temp_path)
            
            try:
                # Upload to Google Drive
                file_id = drive_service.upload_file(temp_path, filename, folder_id)
                if file_id:
                    uploaded_count += 1
                else:
                    error_count += 1
            except Exception as e:
                error_count += 1
                app.logger.error(f"Upload error: {str(e)}")
            finally:
                # Remove temporary file
                if os.path.exists(temp_path):
                    os.remove(temp_path)
        else:
            error_count += 1
    
    if uploaded_count > 0:
        flash(f'Successfully uploaded {uploaded_count} file(s).', 'success')
    if error_count > 0:
        flash(f'Failed to upload {error_count} file(s). Please check file types and try again.', 'danger')
    
    return redirect(url_for('gallery', folder_id=folder_id))

@app.route('/upload/stream', methods=['POST'])
@login_required
def upload_stream():
    """Handle streaming upload directly to Google Drive without saving locally"""
    # Ensure drive service is authenticated
    if not drive_service.service:
        if not drive_service.authenticate():
            return jsonify({
                'success': False,
                'message': 'Could not authenticate with Google Drive. Please check your credentials.'
            }), 500
    
    folder_id = request.form.get('folder_id')
    upload_id = request.form.get('upload_id')  # For resuming uploads
    
    # Check if the request has the file part
    if 'mediaFile' not in request.files:
        return jsonify({
            'success': False,
            'message': 'No file part in the request'
        }), 400
    
    file = request.files['mediaFile']
    
    if file.filename == '':
        return jsonify({
            'success': False,
            'message': 'No selected file'
        }), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        mime_type, _ = mimetypes.guess_type(filename)
        mime_type = mime_type or 'application/octet-stream'
        
        # Get resumable URI if this is a resumed upload
        resumable_uri = None
        if upload_id and upload_id in resumable_uploads:
            resumable_uri = resumable_uploads[upload_id].get('resumable_uri')
        
        # Generate unique ID for this upload to track progress
        if not upload_id:
            upload_id = str(uuid.uuid4())
        
        upload_progress[upload_id] = 0
        
        try:
            # Stream upload directly to Google Drive
            file_id, progress_callback, new_resumable_uri = drive_service.chunked_upload(
                file.stream,
                filename,
                mime_type,
                folder_id,
                resumable_uri=resumable_uri
            )
            
            # Store progress callback for status endpoint
            upload_progress[upload_id] = progress_callback
            
            # Store resumable URI for resuming later if needed
            if new_resumable_uri:
                resumable_uploads[upload_id] = {
                    'resumable_uri': new_resumable_uri,
                    'filename': filename,
                    'mime_type': mime_type,
                    'folder_id': folder_id,
                    'timestamp': time.time()
                }
            elif file_id and upload_id in resumable_uploads:
                # Upload completed, clean up
                del resumable_uploads[upload_id]
            
            if file_id:
                # Upload successful
                return jsonify({
                    'success': True,
                    'message': f'Successfully uploaded {filename}',
                    'file_id': file_id,
                    'upload_id': upload_id
                }), 200
            else:
                # Upload paused/interrupted
                return jsonify({
                    'success': False,
                    'paused': True,
                    'message': 'Upload interrupted but can be resumed',
                    'upload_id': upload_id
                }), 200
        except Exception as e:
            app.logger.error(f"Streaming upload error: {str(e)}")
            return jsonify({
                'success': False,
                'message': f'Error uploading file: {str(e)}',
                'upload_id': upload_id if upload_id in resumable_uploads else None
            }), 500
    else:
        return jsonify({
            'success': False,
            'message': 'File type not allowed'
        }), 400

@app.route('/upload/progress/<upload_id>', methods=['GET'])
@login_required
def upload_progress_status(upload_id):
    """Get the progress of an upload"""
    if upload_id in upload_progress:
        progress = upload_progress[upload_id]
        if callable(progress):
            try:
                percentage = progress()
                return jsonify({
                    'success': True,
                    'progress': percentage
                })
            except Exception as e:
                app.logger.error(f"Error getting upload progress: {str(e)}")
                return jsonify({
                    'success': False,
                    'progress': 0,
                    'message': 'Error getting progress'
                })
        else:
            # If progress is a number, return it directly
            return jsonify({
                'success': True,
                'progress': progress
            })
    else:
        return jsonify({
            'success': False,
            'message': 'Upload ID not found'
        }), 404

@app.route('/upload/resume/<upload_id>', methods=['GET'])
@login_required
def get_resumable_upload_info(upload_id):
    """Get information about a resumable upload"""
    if upload_id in resumable_uploads:
        upload_info = resumable_uploads[upload_id]
        # Don't send back the actual resumable_uri for security
        return jsonify({
            'success': True,
            'can_resume': True,
            'filename': upload_info['filename'],
            'folder_id': upload_info['folder_id'],
            'timestamp': upload_info['timestamp']
        })
    else:
        return jsonify({
            'success': False,
            'can_resume': False,
            'message': 'No resumable upload found'
        }), 404

@app.route('/media/delete/<file_id>', methods=['POST'])
@login_required
@admin_required
def delete_media(file_id):
    folder_id = request.form.get('folder_id', None)
    
    # Ensure drive service is authenticated
    if not drive_service.service:
        if not drive_service.authenticate():
            flash('Could not authenticate with Google Drive. Please check your credentials.', 'danger')
            return redirect(url_for('gallery', folder_id=folder_id))
    
    try:
        # Get file metadata to display name in flash message
        file_metadata = drive_service.get_file_metadata(file_id)
        
        # Delete the file
        if drive_service.delete_file_or_folder(file_id):
            if file_metadata:
                flash(f'File "{file_metadata["name"]}" deleted successfully.', 'success')
            else:
                flash('File deleted successfully.', 'success')
        else:
            flash('Failed to delete file.', 'danger')
    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'danger')
    
    return redirect(url_for('gallery', folder_id=folder_id))

@app.route('/media/view/<file_id>')
@login_required
def view_media(file_id):
    # Ensure drive service is authenticated
    if not drive_service.service:
        if not drive_service.authenticate():
            flash('Could not authenticate with Google Drive. Please check your credentials.', 'danger')
            return redirect(url_for('gallery'))
    
    try:
        # Get file metadata
        file_metadata = drive_service.get_file_metadata(file_id)
        if not file_metadata:
            flash('File not found.', 'danger')
            return redirect(url_for('gallery'))
        
        # Determine content type
        content_type = file_metadata.get('mimeType', 'application/octet-stream')
        is_video = 'video' in content_type
        
        return render_template('view_media.html', 
                              file_id=file_id,
                              file_name=file_metadata['name'],
                              is_video=is_video,
                              content_type=content_type)
    except Exception as e:
        flash(f'Error retrieving file: {str(e)}', 'danger')
        return redirect(url_for('gallery'))

@app.route('/media/download/<file_id>')
@login_required
def download_media(file_id):
    # Ensure drive service is authenticated
    if not drive_service.service:
        if not drive_service.authenticate():
            flash('Could not authenticate with Google Drive. Please check your credentials.', 'danger')
            return redirect(url_for('gallery'))
    
    try:
        # Get file metadata
        file_metadata = drive_service.get_file_metadata(file_id)
        if not file_metadata:
            flash('File not found.', 'danger')
            return redirect(url_for('gallery'))
        
        # Create a temporary file to download to
        filename = secure_filename(file_metadata['name'])
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Download the file
        if drive_service.download_file(file_id, temp_path):
            # Send the file as an attachment
            return send_from_directory(
                directory=app.config['UPLOAD_FOLDER'],
                path=filename,
                as_attachment=True
            )
        else:
            flash('Failed to download file.', 'danger')
            return redirect(url_for('gallery'))
    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'danger')
        return redirect(url_for('gallery'))

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_settings():
    global ADMIN_PASSWORD, MEMBER_PASSWORD, MAX_LOGIN_ATTEMPTS, BLOCK_DURATION_HOURS
    
    password_updated = False
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'change_password':
            # Update passwords
            new_admin_password = request.form.get('admin_password')
            new_member_password = request.form.get('member_password')
            
            if new_admin_password:
                ADMIN_PASSWORD = new_admin_password
                users['admin']['password'] = new_admin_password
            
            if new_member_password:
                MEMBER_PASSWORD = new_member_password
                users['member']['password'] = new_member_password
            
            password_updated = True
            flash('Passwords updated successfully!', 'success')
            
        elif action == 'reset_attempts':
            # Reset failed attempts for an IP
            ip = request.form.get('ip')
            if ip in failed_attempts:
                del failed_attempts[ip]
                flash(f'Failed attempts for IP {ip} have been reset.', 'success')
            
        elif action == 'unblock_ip':
            # Unblock an IP
            ip = request.form.get('ip')
            if ip in blocked_ips:
                del blocked_ips[ip]
                if ip in failed_attempts:
                    del failed_attempts[ip]
                flash(f'IP {ip} has been unblocked.', 'success')
                
        elif action == 'update_settings':
            # Update security settings
            try:
                max_attempts = int(request.form.get('max_attempts', 5))
                block_hours = int(request.form.get('block_hours', 48))
                
                if 1 <= max_attempts <= 10 and 1 <= block_hours <= 72:
                    MAX_LOGIN_ATTEMPTS = max_attempts
                    BLOCK_DURATION_HOURS = block_hours
                    flash('Security settings updated successfully!', 'success')
                else:
                    flash('Invalid settings values. Please check the ranges.', 'danger')
            except ValueError:
                flash('Invalid settings values. Please enter valid numbers.', 'danger')
    
    # Pre-fill password fields with asterisks for visual indication
    admin_password = '*' * 8
    member_password = '*' * 8
    
    return render_template('admin_settings.html', 
                          failed_attempts=failed_attempts,
                          blocked_ips=blocked_ips,
                          password_updated=password_updated,
                          admin_password=admin_password,
                          member_password=member_password,
                          max_attempts=MAX_LOGIN_ATTEMPTS,
                          block_hours=BLOCK_DURATION_HOURS)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

# Custom 404 page
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Add a custom 404 route to handle direct access to gallery URLs
@app.route('/<path:undefined_route>')
def undefined_route_handler(undefined_route):
    return render_template('404.html'), 404

@app.route('/media/thumbnail/<file_id>')
@login_required
def get_thumbnail(file_id):
    # Check cache first
    if file_id in thumbnail_cache:
        cache_entry = thumbnail_cache[file_id]
        # Check if cache entry is still valid
        if time.time() - cache_entry['timestamp'] < CACHE_EXPIRY:
            app.logger.debug(f"Cache HIT for thumbnail {file_id}")
            return cache_entry['data'], 200, {
                'Content-Type': cache_entry['content_type'],
                'Cache-Control': f'public, max-age={CACHE_EXPIRY}',
                'Pragma': 'cache',
                'X-Cache': 'HIT'
            }
        else:
            # Cache expired, remove it
            del thumbnail_cache[file_id]
    
    # Ensure drive service is authenticated
    drive_service = get_drive_service()
    if not drive_service.service:
        if not drive_service.authenticate():
            return redirect(url_for('placeholder_image'))
    
    # Check if upload directory is writable for temporary files
    if not ensure_upload_dir():
        app.logger.warning("Upload directory not writable, serving placeholder instead")
        return redirect(url_for('placeholder_image'))
    
    retry_count = 0
    while retry_count < MAX_API_RETRIES:
        try:
            # Get file metadata to determine content type
            file_metadata = drive_service.get_file_metadata(file_id)
            if not file_metadata:
                app.logger.error(f"File metadata not found for {file_id}")
                return redirect(url_for('placeholder_image'))
                
            content_type = file_metadata.get('mimeType', 'application/octet-stream')
            
            # Use BytesIO where possible to avoid disk I/O on Render
            use_memory = True
            file_size = file_metadata.get('size')
            if file_size and int(file_size) > 5 * 1024 * 1024:  # If larger than 5MB
                use_memory = False  # Use disk for large files
                
            if use_memory:
                # Direct memory approach for small files
                request = drive_service.service.files().get_media(fileId=file_id)
                file_content = BytesIO()
                downloader = MediaIoBaseDownload(file_content, request)
                
                done = False
                while not done:
                    _, done = downloader.next_chunk()
                
                file_content.seek(0)
                file_data = file_content.getvalue()
            else:
                # Create a temporary file to download to
                temp_dir = app.config['UPLOAD_FOLDER']
                temp_file = os.path.join(temp_dir, f"thumb_{file_id}")
                
                # Download the file to temp location
                if drive_service.download_file(file_id, temp_file):
                    try:
                        with open(temp_file, 'rb') as f:
                            file_data = f.read()
                        # Clean up temp file
                        try:
                            os.remove(temp_file)
                        except:
                            pass
                    except Exception as e:
                        app.logger.error(f"Failed to read temporary file: {str(e)}")
                        return redirect(url_for('placeholder_image'))
                else:
                    app.logger.error(f"Failed to download file {file_id}")
                    return redirect(url_for('placeholder_image'))
            
            # Cache the thumbnail if it's not too large
            if len(file_data) < 2 * 1024 * 1024:  # Only cache files smaller than 2MB
                # Remove old entries if cache is full
                if len(thumbnail_cache) >= MAX_CACHE_SIZE:
                    # Remove oldest entry if cache is full
                    oldest_key = min(thumbnail_cache.keys(), key=lambda k: thumbnail_cache[k]['timestamp'])
                    del thumbnail_cache[oldest_key]
                
                thumbnail_cache[file_id] = {
                    'data': file_data,
                    'content_type': content_type,
                    'timestamp': time.time()
                }
            
            # Set cache headers
            response_headers = {
                'Content-Type': content_type,
                'Cache-Control': f'public, max-age={CACHE_EXPIRY}',
                'Pragma': 'cache',
                'X-Cache': 'MISS'
            }
            
            # Return the image with appropriate content type and cache headers
            return file_data, 200, response_headers
        except Exception as e:
            app.logger.error(f"Thumbnail error for {file_id}: {str(e)}")
            retry_count += 1
            
            # If SSL error, force reconnection
            if "SSL" in str(e) or "TLS" in str(e) or isinstance(e, ssl.SSLError):
                app.logger.info("SSL/TLS error detected, reconnecting...")
                drive_service = GoogleDriveService()  # Create a fresh instance
                
            # Wait before retrying
            time.sleep(1 * retry_count)
            
            if retry_count >= MAX_API_RETRIES:
                # Return placeholder image on repeated failure
                return redirect(url_for('placeholder_image'))
    
    # If we get here, all retries failed
    return redirect(url_for('placeholder_image'))

@app.route('/static/img/placeholder')
def placeholder_image():
    # Generate a simple colored placeholder image
    # Create a 200x200 image with a gray background
    img = Image.new('RGB', (200, 200), color=(200, 200, 200))
    draw = ImageDraw.Draw(img)
    
    # Draw an "X" shape from corner to corner
    draw.line([(0, 0), (199, 199)], fill=(150, 150, 150), width=2)
    draw.line([(0, 199), (199, 0)], fill=(150, 150, 150), width=2)
    
    # Save the image to a BytesIO object
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    # Return the image
    return img_io.getvalue(), 200, {
        'Content-Type': 'image/png',
        'Cache-Control': 'public, max-age=86400' # Cache for 24 hours
    }

# Add a function to ensure upload directory exists
def ensure_upload_dir():
    """Ensure the upload directory exists and is writable."""
    upload_dir = app.config['UPLOAD_FOLDER']
    try:
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir, exist_ok=True)
        test_file = os.path.join(upload_dir, '.test_write')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        return True
    except Exception as e:
        app.logger.error(f"Upload directory is not writable: {str(e)}")
        return False

# Check the upload directory at startup
ensure_upload_dir()

if __name__ == '__main__':
    app.run(debug=True)