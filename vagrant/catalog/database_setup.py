import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

    @property
    def serialize(self):
        # Returns object data in easily serializeable format for 'department'
        return {
            'id' : self.id,
            'name' : self.name,
            'email' : self.email,
            'picture' : self.picture
        }

class Department(Base):
    __tablename__ = 'department'

    id = Column(Integer, primary_key=True)
    name = Column(String(40), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        # Returns object data in easily serializeable format for 'department'
        return {
            'id' : self.id,
            'name' : self.name,
            'user_id' : self.user_id
        }

class Application(Base):
    __tablename__ = 'application'

    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    description = Column(String(250))
    department_id = Column(Integer, ForeignKey('department.id'))
    department = relationship(Department)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        # Returns object data in easily serializeable format for 'department'
        return {
            'id' : self.id,
            'name' : self.name,
            'description' : self.description,
            'department' : self.department_id,
            'user_id' : self.user_id

        }


engine = create_engine('sqlite:///departmentapps.db')


Base.metadata.create_all(engine)
