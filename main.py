from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import List
import uvicorn
import shutil
import os
import uuid
from cryptography.fernet import Fernet

app = FastAPI()

# Simulated database
users_db = {}
files_db = {}

SECRET_KEY = "your_jwt_secret_key"
ALGORITHM = "HS256"
fernet_key = Fernet.generate_key()
fernet = Fernet(fernet_key)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

class User(BaseModel):
    email: EmailStr
    password: str
    role: str  # 'ops' or 'client'
    verified: bool = False

class FileMeta(BaseModel):
    file_id: str
    filename: str
    uploaded_by: str

# Helper functions
def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(email: str):
    return users_db.get(email)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        user = get_user(email)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid user")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Routes
@app.post("/signup")
def signup(user: User):
    if user.email in users_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    user.password = get_password_hash(user.password)
    users_db[user.email] = user.dict()
    token = fernet.encrypt(user.email.encode()).decode()
    return {"verification_url": f"/verify-email/{token}"}

@app.get("/verify-email/{token}")
def verify_email(token: str):
    try:
        email = fernet.decrypt(token.encode()).decode()
        users_db[email]["verified"] = True
        return {"message": "Email verified successfully"}
    except:
        raise HTTPException(status_code=400, detail="Invalid token")

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect credentials")
    if user["role"] == "client" and not user["verified"]:
        raise HTTPException(status_code=403, detail="Email not verified")
    access_token = create_access_token(data={"sub": user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/upload")
def upload_file(file: UploadFile = File(...), user=Depends(get_current_user)):
    if user["role"] != "ops":
        raise HTTPException(status_code=403, detail="Not authorized")
    if not file.filename.endswith((".pptx", ".docx", ".xlsx")):
        raise HTTPException(status_code=400, detail="Invalid file type")
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, file_id + "_" + file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    files_db[file_id] = {
        "file_id": file_id,
        "filename": file.filename,
        "uploaded_by": user["email"],
        "path": file_path
    }
    return {"file_id": file_id, "message": "Upload successful"}

@app.get("/files")
def list_files(user=Depends(get_current_user)):
    if user["role"] != "client":
        raise HTTPException(status_code=403, detail="Only client users can list files")
    return list(files_db.values())

@app.get("/download-file/{file_id}")
def generate_download_link(file_id: str, user=Depends(get_current_user)):
    if user["role"] != "client":
        raise HTTPException(status_code=403, detail="Only client users can download files")
    if file_id not in files_db:
        raise HTTPException(status_code=404, detail="File not found")
    token_data = f"{user['email']}|{file_id}"
    encrypted = fernet.encrypt(token_data.encode()).decode()
    return {"download_link": f"/secure-download/{encrypted}", "message": "success"}

@app.get("/secure-download/{token}")
def secure_download(token: str, user=Depends(get_current_user)):
    try:
        decrypted = fernet.decrypt(token.encode()).decode()
        email, file_id = decrypted.split("|")
        if user["email"] != email or user["role"] != "client":
            raise HTTPException(status_code=403, detail="Access denied")
        file_data = files_db.get(file_id)
        if not file_data:
            raise HTTPException(status_code=404, detail="File not found")
        return FileResponse(file_data["path"], filename=file_data["filename"])
    except:
        raise HTTPException(status_code=400, detail="Invalid token")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)