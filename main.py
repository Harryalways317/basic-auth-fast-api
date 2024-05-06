from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel

# Database setup
DATABASE_URL = "sqlite:///./test.db"
Base = declarative_base()
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Integer, default=0)

# Pydantic models
class UserInDB(User):
    pass

class TokenData(BaseModel):
    username: str = None

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(*, data: dict, expires_delta=None):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, "SECRET_KEY", algorithm="HS256")
    return encoded_jwt

app = FastAPI()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/ping")
def ping():
    return {"ping": "pong"}

@app.get("/user/ping")
def user_ping(token: str = Depends(oauth2_scheme)):
    return {"ping": "pong from user"}

@app.get("/admin/ping")
def admin_ping(token: str = Depends(oauth2_scheme)):
    return {"ping": "pong from admin"}

# Initialize the database with default users
def init_db():
    print("Init DB")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Create default admin
        admin_user = User(username='admin', hashed_password=get_password_hash('adminpass'), is_admin=1)
        db.add(admin_user)
        # Create default user
        normal_user = User(username='user', hashed_password=get_password_hash('userpass'), is_admin=0)
        db.add(normal_user)
        db.commit()
        print(admin_user)
        print(normal_user)
    except Exception as e:
        print("Error",e)
        db.rollback()
    finally:
        db.close()
    print("DB initialized")


init_db()
