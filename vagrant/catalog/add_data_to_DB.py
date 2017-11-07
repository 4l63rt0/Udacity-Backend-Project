from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Department, Base, Application, User

engine = create_engine('sqlite:///departmentapps.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="lberto Roch", email="4l63rt.0@gmail.com",
             picture='https://photos.app.goo.gl/S0wvO0ex55h9gJxE2')
session.add(User1)
session.commit()


# Applications for SCADA Department
department1 = Department(user_id=1, name="SCADA")

session.add(department1)
session.commit()

application1 = Application(user_id=1, name="Badge", description="Will display all the transactions for visitors badge access",
                     department=department1)

session.add(application1)
session.commit()

application2 = Application(user_id=1, name="Truck", description="Will display all the transactions for spare trucks",
                     department=department1)

session.add(application2)
session.commit()

application3 = Application(user_id=1, name="Office", description="Will display all the transactions for office keys",
                     department=department1)

session.add(application3)
session.commit()

application4 = Application(user_id=1, name="Equipment", description="Will display all the transactions for heavy equipment",
                     department=department1)

session.add(application4)
session.commit()


# Applications for Office Department
department2 = Department(user_id=1, name="Office")

session.add(department2)
session.commit()

application1 = Application(user_id=1, name="Near Miss", description="Will display all the transactions for Near Miss log",
                     department=department2)

session.add(application1)
session.commit()


print "added departments/apps!"
