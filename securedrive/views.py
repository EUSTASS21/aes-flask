import os
from django.conf import settings
from django.shortcuts import render, redirect
from django.http import FileResponse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from .models import UserFolder


def authenticate_and_get_drive():
    gauth = GoogleAuth()
    try:
        gauth.LoadCredentialsFile("credentials.json")
    except Exception as e:
        print(f"Error loading credentials: {e}")

    try:
        gauth.LoadClientConfigFile("client_secrets.json")
    except Exception as e:
        print(f"Error loading client_secrets.json: {e}")

    if gauth.credentials is None:
        gauth.LocalWebserverAuth()
    elif gauth.access_token_expired:
        gauth.Refresh()
    else:
        gauth.Authorize()

    gauth.SaveCredentialsFile("credentials.json")
    drive = GoogleDrive(gauth)
    return drive


def load_or_generate_key():
    key_path = "aes_key.bin"
    if os.path.exists(key_path):
        with open(key_path, 'rb') as key_file:
            key = key_file.read()
    else:
        key = os.urandom(32)
        with open(key_path, 'wb') as key_file:
            key_file.write(key)
    return key


key = load_or_generate_key()


def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(data) + encryptor.finalize()
    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_data)
    return encrypted_file_path


def create_folder_for_user(user):
    drive = authenticate_and_get_drive()
    folder_metadata = {
        'title': f"Folder_{user.username}",
        'mimeType': 'application/vnd.google-apps.folder'
    }
    folder = drive.CreateFile(folder_metadata)
    folder.Upload()
    return folder['id']


def get_user_folder(user, request):
    # Check if folder_id is stored in session
    folder_id = request.session.get('user_folder_id', None)
    if folder_id:
        return folder_id
    
    try:
        user_folder = UserFolder.objects.get(user=user)
        folder_id = user_folder.folder_id
        request.session['user_folder_id'] = folder_id  # Store in session for future requests
        return folder_id
    except UserFolder.DoesNotExist:
        return None


def upload_to_google_drive(file_path, user, request):
    folder_id = get_user_folder(user, request)
    if folder_id is None:
        return "No folder assigned"

    # Store the last uploaded file path in session (if needed)
    request.session['last_uploaded_file'] = file_path  # This can be used for tracking or further operations

    drive = authenticate_and_get_drive()
    file_drive = drive.CreateFile({'title': os.path.basename(file_path), 'parents': [{'id': folder_id}]})
    file_drive.SetContentFile(file_path)
    file_drive.Upload()
    return "File uploaded successfully!"


def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    decrypted_file_path = file_path.replace('.enc', '')
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)
    return decrypted_file_path


def index(request):
    # Retrieve last upload message or file from the session
    last_upload_message = request.session.get('last_upload_message', None)
    last_uploaded_file = request.session.get('last_uploaded_file', None)

    # Get the username (if the user is authenticated)
    username = request.user.username if request.user.is_authenticated else 'Invité'
    
    return render(request, 'index.html', {
        'last_upload_message': last_upload_message,
        'last_uploaded_file': last_uploaded_file,
        'username': username  # Add the username to the context
    })


def signup(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            folder_id = create_folder_for_user(user)
            UserFolder.objects.create(user=user, folder_id=folder_id)
            return redirect('index')
    else:
        form = UserCreationForm()
    return render(request, 'signup.html', {'form': form})


@login_required
def upload(request):
    if request.method == 'POST' and 'file' in request.FILES:
        file = request.FILES['file']
        file_path = os.path.join(settings.MEDIA_ROOT, file.name)
        with open(file_path, 'wb') as f:
            for chunk in file.chunks():
                f.write(chunk)

        encrypted_file_path = encrypt_file(file_path, key)
        upload_message = upload_to_google_drive(encrypted_file_path, request.user, request)

        # Store upload status in session
        request.session['last_upload_message'] = upload_message  # Store last upload message

        os.remove(file_path)
        os.remove(encrypted_file_path)

        return render(request, 'index.html', {'message': upload_message})

    return redirect('index')


@login_required
def list_files(request):
    drive = authenticate_and_get_drive()
    folder_id = get_user_folder(request.user, request)  # Get the user's folder ID

    if not folder_id:
        return render(request, 'download.html', {'files': [], 'message': "No folder found for the user."})

    # List files only in the user's Google Drive folder
    query = f"'{folder_id}' in parents and title contains '.enc'"
    file_list = drive.ListFile({'q': query}).GetList()
    
    return render(request, 'download.html', {'files': file_list})


@login_required
def download_file(request, file_id):
    drive = authenticate_and_get_drive()
    file_drive = drive.CreateFile({'id': file_id})
    encrypted_file_path = os.path.join(settings.MEDIA_ROOT, file_drive['title'])
    file_drive.GetContentFile(encrypted_file_path)

    decrypted_file_path = decrypt_file(encrypted_file_path, key)
    os.remove(encrypted_file_path)

    return FileResponse(open(decrypted_file_path, 'rb'), as_attachment=True)
