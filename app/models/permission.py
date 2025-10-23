from sqlalchemy import Column, Integer, String, Enum
from sqlalchemy.orm import relationship
from app.core.db import Base
from .user import OrganizationType


class Permission(Base):
    __tablename__ = "permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    organization_type = Column(Enum(OrganizationType), nullable=False)  # Changed to Enum
    organization_id = Column(Integer, nullable=False)
    roles = relationship("Role", secondary="role_permissions", back_populates="permissions")