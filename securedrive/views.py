import os
from django.conf import settings
from django.shortcuts import render, redirect
from django.http import HttpResponse, FileResponse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
from django.contrib.auth.forms import UserCreationForm

gauth = GoogleAuth()
# Load credentials and authenticate
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

FOLDER_ID = '13r08X0-Q3I4zUT_75iIXO7upSEZsqwUB'

def upload_to_google_drive(file_path):
    file_drive = drive.CreateFile({'title': os.path.basename(file_path), 'parents': [{'id': FOLDER_ID}]})
    file_drive.SetContentFile(file_path)
    file_drive.Upload()

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
    return render(request, 'index.html')

def signup(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()  # Save the user to the database
            return redirect('login')  # Redirect to the login page after successful signup
    else:
        form = UserCreationForm()
    return render(request, 'signup.html', {'form': form})

def upload(request):
    if request.method == 'POST' and 'file' in request.FILES:
        file = request.FILES['file']
        file_path = os.path.join(settings.MEDIA_ROOT, file.name)
        with open(file_path, 'wb') as f:
            for chunk in file.chunks():
                f.write(chunk)

        encrypted_file_path = encrypt_file(file_path, key)
        upload_to_google_drive(encrypted_file_path)

        os.remove(file_path)
        os.remove(encrypted_file_path)

        return render(request, 'index.html', {'message': "File uploaded successfully!"})

    return redirect('index')

def list_files(request):
    file_list = drive.ListFile({'q': "title contains '.enc'"}).GetList()
    return render(request, 'download.html', {'files': file_list})

def download_file(request, file_id):
    file_drive = drive.CreateFile({'id': file_id})
    encrypted_file_path = os.path.join(settings.MEDIA_ROOT, file_drive['title'])
    file_drive.GetContentFile(encrypted_file_path)

    decrypted_file_path = decrypt_file(encrypted_file_path, key)
    os.remove(encrypted_file_path)

    return FileResponse(open(decrypted_file_path, 'rb'), as_attachment=True)
