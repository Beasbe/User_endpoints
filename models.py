from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base


class Role(Base):
    __tablename__ = 'roles'

    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    users = relationship("User", back_populates="role")
    access_rules = relationship("AccessRoleRule", back_populates="role", cascade="all, delete-orphan")


class BusinessElement(Base):
    __tablename__ = 'business_elements'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    table_name = Column(String(100))  # Название таблицы в БД
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    access_rules = relationship("AccessRoleRule", back_populates="business_element", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<BusinessElement(id={self.id}, name='{self.name}')>"


class AccessRoleRule(Base):
    __tablename__ = 'access_roles_rules'

    id = Column(Integer, primary_key=True)
    role_id = Column(Integer, ForeignKey('roles.id', ondelete='CASCADE'), nullable=False)
    element_id = Column(Integer, ForeignKey('business_elements.id', ondelete='CASCADE'), nullable=False)

    read_permission = Column(Boolean, default=False)
    read_all_permission = Column(Boolean, default=False)
    create_permission = Column(Boolean, default=False)
    update_permission = Column(Boolean, default=False)
    update_all_permission = Column(Boolean, default=False)
    delete_permission = Column(Boolean, default=False)
    delete_all_permission = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    role = relationship("Role", back_populates="access_rules")
    business_element = relationship("BusinessElement", back_populates="access_rules")

    __table_args__ = (
        UniqueConstraint('role_id', 'element_id', name='uq_role_element'),
    )

    def __repr__(self):
        return f"<AccessRoleRule(role_id={self.role_id}, element_id={self.element_id})>"


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    patronymic = Column(String(100), nullable=True)
    email = Column(String(150), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    role_id = Column(Integer, ForeignKey('roles.id'), default=1)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    deleted_at = Column(DateTime, nullable=True)


    role = relationship("Role", back_populates="users")

    def __repr__(self):
        return f"<User(id={self.id}, email='{self.email}')>"

    def soft_delete(self):
        """Мягкое удаление пользователя"""
        self.is_active = False
        self.deleted_at = datetime.utcnow()

    def restore(self):
        """Восстановление пользователя"""
        self.is_active = True
        self.deleted_at = None


class Product(Base):
    __tablename__ = 'products'

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    price = Column(Integer)
    owner_id = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.utcnow)

    # Асинхронная связь
    owner = relationship("User")

    def __repr__(self):
        return f"<Product(id={self.id}, name='{self.name}')>"