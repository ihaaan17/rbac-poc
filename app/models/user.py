from sqlalchemy import Column, Integer, String, Enum
from sqlalchemy.orm import relationship
from app.core.db import Base
import enum

class OrganizationType(enum.Enum):
    SCHOOL = "SCHOOL"
    UNIVERSITY = "UNIVERSITY"
    COMPANY = "COMPANY"

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    organization_type = Column(Enum(OrganizationType), nullable=False)
    organization_id = Column(Integer, nullable=False)
    roles = relationship("Role", secondary="user_roles", back_populates="users")