from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from googleapiclient.errors import HttpError
import mimetypes
import os
import io
import time
import random
import socket
import ssl
import logging
import json
import base64

SCOPES = ['https://www.googleapis.com/auth/drive']
SERVICE_ACCOUNT_FILE = 'service_account.json'  # Local file path
ROOT_FOLDER_ID = os.environ.get('ROOT_FOLDER_ID', '1grRUMpHzqMuIYY_mmsNrRJdFuTOgvPLt')   # Shared folder ID from environment

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gdrive")

# Maximum number of retries for API calls
MAX_RETRIES = int(os.environ.get('MAX_DRIVE_RETRIES', '5'))

class GoogleDriveService:
    def __init__(self):
        self.creds = None
        self.service = None
        self.root_folder_id = ROOT_FOLDER_ID
        self.authenticate()
        
    def authenticate(self):
        """Initialize the Drive API client with retry mechanism."""
        try:
            # First try to use the local service account file
            if os.path.exists(SERVICE_ACCOUNT_FILE):
                logger.info(f"Using service account file: {SERVICE_ACCOUNT_FILE}")
                self.creds = service_account.Credentials.from_service_account_file(
                    SERVICE_ACCOUNT_FILE,
                    scopes=SCOPES
                )
            else:
                # Fall back to environment variable if file not found
                logger.info("Service account file not found, checking environment variable")
                service_account_json = os.environ.get('GOOGLE_SERVICE_ACCOUNT_JSON')
                
                if service_account_json:
                    # Credentials provided as environment variable (for Render)
                    try:
                        # Try to parse directly if it's a JSON string
                        service_account_info = json.loads(service_account_json)
                    except json.JSONDecodeError:
                        # If not valid JSON, try as base64
                        try:
                            service_account_info = json.loads(base64.b64decode(service_account_json).decode('utf-8'))
                        except:
                            logger.error("Failed to decode service account JSON from environment variable")
                            return False
                    
                    self.creds = service_account.Credentials.from_service_account_info(
                        service_account_info,
                        scopes=SCOPES
                    )
                else:
                    logger.error("No service account credentials found (file or environment)")
                    return False
                
            self.service = build('drive', 'v3', credentials=self.creds, cache_discovery=False)
            return True
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return False

    def _execute_with_retry(self, request):
        """Execute a request with exponential backoff retry."""
        retry = 0
        while retry < MAX_RETRIES:
            try:
                return request.execute()
            except (HttpError, socket.error, ssl.SSLError, ConnectionError) as e:
                retry += 1
                if retry >= MAX_RETRIES:
                    logger.error(f"API request failed after {MAX_RETRIES} retries. Error: {str(e)}")
                    raise
                
                # Check if error is related to authentication
                if isinstance(e, HttpError) and e.resp.status in [401, 403]:
                    logger.info("Authentication error, attempting to re-authenticate...")
                    self.authenticate()
                    
                # Exponential backoff with jitter
                wait_time = (2 ** retry) + random.random()
                logger.info(f"API request failed. Retrying in {wait_time:.2f} seconds...")
                time.sleep(wait_time)
                
                # If SSL error, rebuild the service
                if isinstance(e, ssl.SSLError) or "SSL" in str(e):
                    logger.info("SSL error detected, rebuilding service...")
                    self.authenticate()

    def get_folder_contents(self, folder_id=None):
        """Get contents of a folder with retry mechanism."""
        if not folder_id:
            folder_id = self.root_folder_id
        if not self.service:
            if not self.authenticate():
                return []
                
        query = f"'{folder_id}' in parents and trashed=false"
        request = self.service.files().list(
            q=query,
            spaces='drive',
            fields='files(id, name, mimeType, createdTime, modifiedTime)'
        )
        
        try:
            results = self._execute_with_retry(request)
            return results.get('files', [])
        except Exception as e:
            logger.error(f"Error getting folder contents: {str(e)}")
            return []

    def upload_file(self, file_path, filename=None, parent_id=None):
        """Upload a file with retry mechanism."""
        if not parent_id:
            parent_id = self.root_folder_id
        if not filename:
            filename = os.path.basename(file_path)
        if not self.service:
            if not self.authenticate():
                return None
                
        mime_type, _ = mimetypes.guess_type(file_path)
        mime_type = mime_type or 'application/octet-stream'
        metadata = {'name': filename, 'parents': [parent_id]}
        
        try:
            media = MediaFileUpload(file_path, mimetype=mime_type, resumable=True)
            request = self.service.files().create(body=metadata, media_body=media, fields='id')
            file = self._execute_with_retry(request)
            return file.get('id')
        except Exception as e:
            logger.error(f"Error uploading file: {str(e)}")
            return None

    def download_file(self, file_id, output_path):
        """Download a file with retry mechanism."""
        if not self.service:
            if not self.authenticate():
                return False
                
        try:
            request = self.service.files().get_media(fileId=file_id)
            fh = io.FileIO(output_path, 'wb')
            downloader = MediaIoBaseDownload(fh, request)
            
            done = False
            retry_count = 0
            
            while not done and retry_count < MAX_RETRIES:
                try:
                    status, done = downloader.next_chunk()
                except (HttpError, socket.error, ssl.SSLError, ConnectionError) as e:
                    retry_count += 1
                    if retry_count >= MAX_RETRIES:
                        logger.error(f"Download failed after {MAX_RETRIES} retries: {str(e)}")
                        return False
                    
                    # Exponential backoff with jitter
                    wait_time = (2 ** retry_count) + random.random()
                    logger.info(f"Download chunk failed. Retrying in {wait_time:.2f} seconds...")
                    time.sleep(wait_time)
                    
                    # If SSL error, rebuild the service
                    if isinstance(e, ssl.SSLError) or "SSL" in str(e):
                        logger.info("SSL error detected, rebuilding service...")
                        self.authenticate()
                        # Need to recreate the request and downloader
                        request = self.service.files().get_media(fileId=file_id)
                        downloader = MediaIoBaseDownload(fh, request)
            
            fh.close()
            return done
        except Exception as e:
            logger.error(f"Error downloading file: {str(e)}")
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except:
                    pass
            return False

    def delete_file_or_folder(self, file_id):
        """Delete a file or folder with retry mechanism."""
        if not self.service:
            if not self.authenticate():
                return False
                
        try:
            request = self.service.files().delete(fileId=file_id)
            self._execute_with_retry(request)
            return True
        except Exception as e:
            logger.error(f"Error deleting file: {str(e)}")
            return False

    def get_file_metadata(self, file_id):
        """Get file metadata with retry mechanism."""
        if not self.service:
            if not self.authenticate():
                return None
                
        try:
            request = self.service.files().get(
                fileId=file_id,
                fields='id, name, mimeType, size, createdTime, modifiedTime'
            )
            return self._execute_with_retry(request)
        except Exception as e:
            logger.error(f"Error getting file metadata: {str(e)}")
            return None
            
    def create_folder(self, folder_name, parent_id=None):
        """Create a folder with retry mechanism."""
        if not parent_id:
            parent_id = self.root_folder_id
        if not self.service:
            if not self.authenticate():
                return None
                
        try:
            folder_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder',
                'parents': [parent_id]
            }
            
            request = self.service.files().create(
                body=folder_metadata,
                fields='id'
            )
            folder = self._execute_with_retry(request)
            return folder.get('id')
        except Exception as e:
            logger.error(f"Error creating folder: {str(e)}")
            return None

    def ensure_root_folder(self):
        """Ensure the root folder exists."""
        # Just check if we can access it
        if self.get_file_metadata(self.root_folder_id):
            return self.root_folder_id
        return None