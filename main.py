from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from app.core.db import SessionLocal, Base, engine
from app.models import User, Role, Permission, user_roles, role_permissions
from app.core.jwt import create_access_token, verify_token
from app.core.config import settings
from datetime import timedelta

app = FastAPI(title="RBAC POC")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

# Dependency for database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Dependency to get current user from JWT
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = verify_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    email = payload.get("sub")
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# Dependency to check if user has permission
def has_permission(permission_name: str):
    def check_permission(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
        for role in user.roles:
            for permission in role.permissions:
                if permission.name == permission_name:
                    return True
        raise HTTPException(status_code=403, detail=f"Insufficient permissions: {permission_name} required")
    return check_permission

# Create database tables
Base.metadata.create_all(bind=engine)

# Placeholder sub-apps
school_app = FastAPI(title="School API")
university_app = FastAPI(title="University API")
company_app = FastAPI(title="Company API")

# Mount sub-apps
app.mount("/api/school", school_app)
app.mount("/api/university", university_app)
app.mount("/api/company", company_app)

# Registration endpoint (public)
@app.post("/apiister")
async def register(email: str, password: str, organization_type: str, organization_id: int, db: Session = Depends(get_db)):
    if organization_type not in ["SCHOOL", "UNIVERSITY", "COMPANY"]:
        raise HTTPException(status_code=400, detail="Invalid organization type")
    db_user = db.query(User).filter(User.email == email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = pwd_context.hash(password[:72])
    db_user = User(
        email=email,
        password_hash=hashed_password,
        organization_type=organization_type,
        organization_id=organization_id
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"message": "User registered successfully"}

# Login endpoint (public)
@app.post("/api/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == form_data.username).first()
    if not db_user or not pwd_context.verify(form_data.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(
        data={"sub": db_user.email, "org_type": db_user.organization_type},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Health check (public)
@app.get("/health")
async def health():
    return {"status": "ok"}

# Utility API 1: Create new student (user type) - Protected by JWT and 'create_user' permission
@school_app.post("/{school_id}/create-student")
async def create_student(school_id: int, student_email: str, student_password: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user), permission: bool = Depends(has_permission("create_user"))):
    if current_user.organization_type != "school" or current_user.organization_id != school_id:
        raise HTTPException(status_code=403, detail="Access denied to this school")
    db_student = db.query(User).filter(User.email == student_email).first()
    if db_student:
        raise HTTPException(status_code=400, detail="Student email already registered")
    hashed_password = pwd_context.hash(student_password)
    db_student = User(
        email=student_email,
        password_hash=hashed_password,
        organization_type="school",
        organization_id=school_id
    )
    db.add(db_student)
    db.commit()
    db.refresh(db_student)
    return {"message": "Student created successfully", "student_id": db_student.id}

# Utility API 2: Assign education manager to a student - Protected by JWT and 'assign_manager' permission
@school_app.post("/{school_id}/assign-education-manager")
async def assign_education_manager(school_id: int, student_id: int, manager_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user), permission: bool = Depends(has_permission("assign_manager"))):
    if current_user.organization_type != "school" or current_user.organization_id != school_id:
        raise HTTPException(status_code=403, detail="Access denied to this school")
    student = db.query(User).filter(User.id == student_id, User.organization_type == "school", User.organization_id == school_id).first()
    manager = db.query(User).filter(User.id == manager_id, User.organization_type == "school", User.organization_id == school_id).first()
    if not student or not manager:
        raise HTTPException(status_code=404, detail="Student or manager not found")
    return {"message": "Education manager assigned to student successfully"}

# Utility API 3: Create new role - Protected by JWT and 'create_role' permission
@app.post("/api/{org_type}/{org_id}/create-role")
async def create_role(org_type: str, org_id: int, role_name: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user), permission: bool = Depends(has_permission("create_role"))):
    if current_user.organization_type != org_type or current_user.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied to this organization")
    if org_type not in ["school", "university", "company"]:
        raise HTTPException(status_code=400, detail="Invalid organization type")
    db_role = db.query(Role).filter(Role.name == role_name, Role.organization_type == org_type, Role.organization_id == org_id).first()
    if db_role:
        raise HTTPException(status_code=400, detail="Role already exists")
    db_role = Role(
        name=role_name,
        organization_type=org_type,
        organization_id=org_id
    )
    db.add(db_role)
    db.commit()
    db.refresh(db_role)
    return {"message": "Role created successfully", "role_id": db_role.id}

# Utility API 4: Assign permission to role - Protected by JWT and 'assign_permission' permission
@app.post("/api/{org_type}/{org_id}/assign-permission")
async def assign_permission(org_type: str, org_id: int, role_id: int, permission_name: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user), permission: bool = Depends(has_permission("assign_permission"))):
    if current_user.organization_type != org_type or current_user.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied to this organization")
    if org_type not in ["school", "university", "company"]:
        raise HTTPException(status_code=400, detail="Invalid organization type")
    db_role = db.query(Role).filter(Role.id == role_id, Role.organization_type == org_type, Role.organization_id == org_id).first()
    if not db_role:
        raise HTTPException(status_code=404, detail="Role not found")
    db_permission = db.query(Permission).filter(Permission.name == permission_name, Permission.organization_type == org_type, Permission.organization_id == org_id).first()
    if not db_permission:
        db_permission = Permission(
            name=permission_name,
            organization_type=org_type,
            organization_id=org_id
        )
        db.add(db_permission)
        db.commit()
        db.refresh(db_permission)
    if db_permission not in db_role.permissions:
        db_role.permissions.append(db_permission)
        db.commit()
    return {"message": "Permission assigned to role successfully"}

# Utility API 5: Access document (protected by 'access_document' permission)
@school_app.get("/{school_id}/documents/{document_id}")
async def access_document(school_id: int, document_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user), permission: bool = Depends(has_permission("access_document"))):
    if current_user.organization_type != "school" or current_user.organization_id != school_id:
        raise HTTPException(status_code=403, detail="Access denied to this school")
    return {"message": "Document accessed successfully", "document_id": document_id}

# New Utility API 6: Assign role to user - Protected by JWT and 'assign_role' permission
@app.post("/api/{org_type}/{org_id}/assign-role")
async def assign_role(org_type: str, org_id: int, user_id: int, role_name: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user), permission: bool = Depends(has_permission("assign_role"))):
    if current_user.organization_type != org_type or current_user.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied to this organization")
    if org_type not in ["school", "university", "company"]:
        raise HTTPException(status_code=400, detail="Invalid organization type")
    db_user = db.query(User).filter(User.id == user_id, User.organization_type == org_type, User.organization_id == org_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    db_role = db.query(Role).filter(Role.name == role_name, Role.organization_type == org_type, Role.organization_id == org_id).first()
    if not db_role:
        raise HTTPException(status_code=404, detail="Role not found")
    if db_role not in db_user.roles:
        db_user.roles.append(db_role)
        db.commit()
    return {"message": "Role assigned to user successfully"}

# New Utility API 7: List users in organization - Protected by JWT and 'list_users' permission
@app.get("/api/{org_type}/{org_id}/users")
async def list_users(org_type: str, org_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user), permission: bool = Depends(has_permission("list_users"))):
    if current_user.organization_type != org_type or current_user.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied to this organization")
    if org_type not in ["SCHOOL", "UNIVERSITY", "COMPANY"]:
        raise HTTPException(status_code=400, detail="Invalid org1anization type")
    users = db.query(User).filter(User.organization_type == org_type, User.organization_id == org_id).all()
    return [
        {
            "id": user.id,
            "email": user.email,
            "organization_type": user.organization_type,
            "organization_id": user.organization_id,
            "roles": [role.name for role in user.roles]
        }
        for user in users
    ]