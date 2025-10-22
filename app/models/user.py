from sqlalchemy import Column, Integer, String, Enum, ForeignKey
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
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True)
    organization_type = Column(Enum(OrganizationType), nullable=False)
    password_hash = Column(String, nullable=False)
    organization_id = Column(Integer, nullable=False)

    # relationships
    roles = relationship("Role", secondary="user_roles", back_populates="users")
