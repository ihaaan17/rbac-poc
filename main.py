from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from app.core.db import SessionLocal, Base, engine
from app.models import User, Role, Permission, user_roles, role_permissions
from app.core.jwt import create_access_token, verify_token
from app.core.config import settings

# Initialize FastAPI app
app = FastAPI(title="RBAC POC")

# Password hashing - using Argon2 (recommended)
password_hash = PasswordHash((Argon2Hasher(),))

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

# Database session dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Decode and validate JWT to get current user
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

# Permission dependency
def has_permission(permission_name: str):
    def check_permission(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
        for role in user.roles:
            for permission in role.permissions:
                if permission.name == permission_name:
                    return True
        raise HTTPException(status_code=403, detail=f"Permission '{permission_name}' required")
    return check_permission

# Create DB schema
Base.metadata.create_all(bind=engine)

# Sub‑applications
school_app = FastAPI(title="School API")
university_app = FastAPI(title="University API")
company_app = FastAPI(title="Company API")

app.mount("/api/school", school_app)
app.mount("/api/university", university_app)
app.mount("/api/company", company_app)

# Health check
@app.get("/health")
async def health():
    return {"status": "ok"}

# Bootstrap endpoint - FOR TESTING ONLY, REMOVE IN PRODUCTION
@app.post("/api/bootstrap")
async def bootstrap(email: str, db: Session = Depends(get_db)):
    """Create initial admin user with all permissions - USE ONLY FOR TESTING"""
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found. Register first.")
    
    # Extract the string value from the enum
    org_type = user.organization_type.value
    org_id = user.organization_id
    
    created_items = {
        "role_created": False,
        "permissions_created": [],
        "permissions_assigned": [],
        "role_assigned": False
    }
    
    # Create admin role
    admin_role = db.query(Role).filter(
        Role.name == "admin",
        Role.organization_type == org_type,
        Role.organization_id == org_id
    ).first()
    
    if not admin_role:
        admin_role = Role(name="admin", organization_type=org_type, organization_id=org_id)
        db.add(admin_role)
        db.commit()
        db.refresh(admin_role)
        created_items["role_created"] = True
    
    # Create all permissions
    permission_names = [
        "create_user", "assign_manager", "create_role", 
        "assign_permission", "access_document", "assign_role", "list_users"
    ]
    
    for perm_name in permission_names:
        perm = db.query(Permission).filter(
            Permission.name == perm_name,
            Permission.organization_type == org_type,
            Permission.organization_id == org_id
        ).first()
        
        if not perm:
            perm = Permission(name=perm_name, organization_type=org_type, organization_id=org_id)
            db.add(perm)
            db.commit()
            db.refresh(perm)
            created_items["permissions_created"].append(perm_name)
        
        if perm not in admin_role.permissions:
            admin_role.permissions.append(perm)
            created_items["permissions_assigned"].append(perm_name)
    
    db.commit()  # Important: commit after adding all permissions
    
    # Assign admin role to user
    if admin_role not in user.roles:
        user.roles.append(admin_role)
        created_items["role_assigned"] = True
        db.commit()
    
    return {
        "message": "User bootstrapped as admin with all permissions",
        "user_id": user.id,
        "user_email": email,
        "role_id": admin_role.id,
        "role": "admin",
        "org_type": org_type,
        "org_id": org_id,
        "details": created_items,
        "total_permissions": len(admin_role.permissions)
    }
@app.post("/api/register")
async def register(email: str, password: str, organization_type: str, organization_id: int, db: Session = Depends(get_db)):
    # Normalize organization type to uppercase
    organization_type = organization_type.upper()
    
    if organization_type not in ["SCHOOL", "UNIVERSITY", "COMPANY"]:
        raise HTTPException(status_code=400, detail="Invalid organization type")

    db_user = db.query(User).filter(User.email == email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = password_hash.hash(password)
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

# Login endpoint
@app.post("/api/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not password_hash.verify(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(
        data={"sub": user.email, "org_type": user.organization_type},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

# School: create student
@school_app.post("/{school_id}/create-student")
async def create_student(school_id: int, student_email: str, student_password: str, db: Session = Depends(get_db),
                         current_user: User = Depends(get_current_user),
                         permission: bool = Depends(has_permission("create_user"))):
    if current_user.organization_type != "SCHOOL" or current_user.organization_id != school_id:
        raise HTTPException(status_code=403, detail="Access denied to this school")

    if db.query(User).filter(User.email == student_email).first():
        raise HTTPException(status_code=400, detail="Student email already registered")

    hashed_password = password_hash.hash(student_password)
    db_student = User(
        email=student_email,
        password_hash=hashed_password,
        organization_type="SCHOOL",
        organization_id=school_id
    )
    db.add(db_student)
    db.commit()
    db.refresh(db_student)
    return {"message": "Student created successfully", "student_id": db_student.id}

# Assign education manager
@school_app.post("/{school_id}/assign-education-manager")
async def assign_education_manager(school_id: int, student_id: int, manager_id: int, db: Session = Depends(get_db),
                                   current_user: User = Depends(get_current_user),
                                   permission: bool = Depends(has_permission("assign_manager"))):
    if current_user.organization_type != "SCHOOL" or current_user.organization_id != school_id:
        raise HTTPException(status_code=403, detail="Access denied to this school")

    student = db.query(User).filter(User.id == student_id, User.organization_type == "SCHOOL", User.organization_id == school_id).first()
    manager = db.query(User).filter(User.id == manager_id, User.organization_type == "SCHOOL", User.organization_id == school_id).first()

    if not student or not manager:
        raise HTTPException(status_code=404, detail="Student or manager not found")

    return {"message": "Education manager assigned successfully"}

# Create role
# Create role
@app.post("/api/{org_type}/{org_id}/create-role")
async def create_role(org_type: str, org_id: int, role_name: str, db: Session = Depends(get_db),
                      current_user: User = Depends(get_current_user),
                      permission: bool = Depends(has_permission("create_role"))):
    # Normalize organization type to uppercase
    org_type = org_type.upper()
    # Convert enum to string for comparison
    user_org_type = current_user.organization_type.value if hasattr(current_user.organization_type, 'value') else current_user.organization_type
    if user_org_type != org_type or current_user.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")
    if org_type not in ["SCHOOL", "UNIVERSITY", "COMPANY"]:
        raise HTTPException(status_code=400, detail="Invalid organization type")
    db_role = db.query(Role).filter(Role.name == role_name,
                                    Role.organization_type == org_type,
                                    Role.organization_id == org_id).first()
    if db_role:
        raise HTTPException(status_code=400, detail="Role already exists")
    db_role = Role(name=role_name, organization_type=org_type, organization_id=org_id)
    db.add(db_role)
    db.commit()
    db.refresh(db_role)
    return {"message": "Role created successfully", "role_id": db_role.id}
@app.post("/api/{org_type}/{org_id}/assign-permission")
async def assign_permission(org_type: str, org_id: int, role_id: int, permission_name: str,
                            db: Session = Depends(get_db),
                            current_user: User = Depends(get_current_user),
                            permission: bool = Depends(has_permission("assign_permission"))):
    # Normalize organization type to uppercase
    org_type = org_type.upper()
    if  current_user.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")
    db_role = db.query(Role).filter(Role.id == role_id,
                                    Role.organization_type == org_type,
                                    Role.organization_id == org_id).first()
    if not db_role:
        raise HTTPException(status_code=404, detail="Role not found")
    db_permission = db.query(Permission).filter(Permission.name == permission_name,
                                                Permission.organization_type == org_type,
                                                Permission.organization_id == org_id).first()
    if not db_permission:
        db_permission = Permission(name=permission_name, organization_type=org_type, organization_id=org_id)
        db.add(db_permission)
        db.commit()
        db.refresh(db_permission)
    if db_permission not in db_role.permissions:
        db_role.permissions.append(db_permission)
        db.commit()
    return {"message": "Permission assigned successfully"}
# Access protected document
@school_app.get("/{school_id}/documents/{document_id}")
async def access_document(school_id: int, document_id: int, db: Session = Depends(get_db),
                          current_user: User = Depends(get_current_user),
                          permission: bool = Depends(has_permission("access_document"))):
    if current_user.organization_type != "SCHOOL" or current_user.organization_id != school_id:
        raise HTTPException(status_code=403, detail="Access denied to this school")
    return {"message": "Document accessed successfully", "document_id": document_id}

# Assign role to user
@app.post("/api/{org_type}/{org_id}/assign-role")
async def assign_role(org_type: str, org_id: int, user_id: int, role_name: str, db: Session = Depends(get_db),
                      current_user: User = Depends(get_current_user),
                      permission: bool = Depends(has_permission("assign_role"))):
    # Normalize organization type to uppercase
    org_type = org_type.upper()
    
    if  current_user.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    db_user = db.query(User).filter(User.id == user_id,
                                    User.organization_type == org_type,
                                    User.organization_id == org_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db_role = db.query(Role).filter(Role.name == role_name,
                                    Role.organization_type == org_type,
                                    Role.organization_id == org_id).first()
    if not db_role:
        raise HTTPException(status_code=404, detail="Role not found")

    if db_role not in db_user.roles:
        db_user.roles.append(db_role)
        db.commit()
    return {"message": "Role assigned successfully"}

# List users in organization
@app.get("/api/{org_type}/{org_id}/users")
async def list_users(org_type: str, org_id: int, db: Session = Depends(get_db),
                     current_user: User = Depends(get_current_user),
                     permission: bool = Depends(has_permission("list_users"))):
    # Normalize organization type to uppercase
    org_type = org_type.upper()
    
    if current_user.organization_type != org_type or current_user.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    users = db.query(User).filter(User.organization_type == org_type, User.organization_id == org_id).all()
    return [
        {
            "id": u.id,
            "email": u.email,
            "organization_type": u.organization_type,
            "organization_id": u.organization_id,
            "roles": [r.name for r in u.roles]
        }
        for u in users
    ]