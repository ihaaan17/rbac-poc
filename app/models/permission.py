from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship
from app.core.db import Base

class Permission(Base):
    __tablename__ = "permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    organization_type = Column(String, nullable=False)
    organization_id = Column(Integer, nullable=False)
    roles = relationship("Role", secondary="role_permissions", back_populates="permissions")