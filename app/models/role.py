from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship
from app.core.db import Base
from .user import OrganizationType

class Role(Base):
    __tablename__ = "roles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    organization_type = Column(String, nullable=False)
    organization_id = Column(Integer, nullable=False)
    users = relationship("User", secondary="user_roles", back_populates="roles")
    permissions = relationship("Permission", secondary="role_permissions", back_populates="roles")