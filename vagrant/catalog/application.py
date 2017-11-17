from flask import (Flask, render_template, request,
                   redirect, url_for, flash, jsonify, make_response,
                   session as login_session)
import httplib2, json, requests, random, string
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Department, Application, User
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError


app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "SM Energy - Department Apps"

# Add Edit, Delete Option inside Apps Description
# Add logged username in every page
# Add Go Back button
# Do not repeat departments and apps names

engine = create_engine('sqlite:///departmentapps.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind = engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token


    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 150px; height: 150px;border-radius: 75px;-webkit-border-radius: 75px;-moz-border-radius: 75px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return redirect(url_for('departments'))


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('departments'))
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('departments'))
    else:
        flash("You were not logged in")
        return redirect(url_for('index'))


# API Endpoint for all departments
@app.route('/departments/JSON')
def departmentsListJSON():
    allDepartments = session.query(Department).all()
    return jsonify(departmentsList = [i.serialize for i in allDepartments])


@app.route('/allUsers/JSON')
def usersListJSON():
    allUsers = session.query(User).all()
    return jsonify(userList = [i.serialize for i in allUsers])


# API Endpoint for all apps inside a department_id
@app.route('/department/<int:department_id>/JSON')
def departmentAppsListJSON(department_id):
    department = session.query(Department).filter_by(id = department_id).one()
    apps = session.query(Application).filter_by(department_id = department.id)
    return jsonify(departmentAppList = [i.serialize for i in apps])


# API Endpoint for specific app
@app.route('/department/<int:department_id>/App/<int:application_id>/JSON')
def departmentAppsDescJSON(department_id, application_id):
    department = session.query(Department).filter_by(id = department_id).one()
    apps = session.query(Application).filter_by(id = application_id).one()
    return jsonify(departmentAppList = [apps.serialize])


# Index route of this application
@app.route('/')
@app.route('/index')
@app.route('/main')
def home():
    return


@app.route('/jquery')
def jquery():
    return render_template('jquery.html')


@app.route('/about')
def about():
    if 'username' not in login_session:
        return render_template('about.html')
    else:
        return render_template('about.html',
            userPicture=login_session['picture'])


@app.route('/contactus')
def contactus():
    if 'username' not in login_session:
        return render_template('contactus.html')
    else:
        return render_template('contactus.html',
            userPicture=login_session['picture'])


@app.route('/departments')
def departments():
    allDepartments = session.query(Department).all()
    for i in allDepartments:
        print
    if 'username' not in login_session:
        return render_template('publicAllDepartments.html',
            allDep = allDepartments, department_id = i.id)
    if allDepartments == []:
        noDep = 'Create your own department'
        return render_template('newDepartment.html', noDep=noDep,
            userEmail=login_session['email'],
            userPicture=login_session['picture'])
    else:
        return render_template('AllDepartments.html',
            allDep = allDepartments, department_id = i.id,
            userEmail=login_session['email'],
            loggedUser=login_session['user_id'],
            userPicture=login_session['picture'],
            userId=login_session['user_id'])


@app.route('/department/<int:department_id>/')
def departmentApps(department_id):
    department=session.query(Department).filter_by(id=department_id).one()
    apps=session.query(Application).filter_by(department_id=department.id).all()
    for i in apps:
        print
    if apps == []:
        appsValue = True
    else:
        appsValue = False
    if 'username' not in login_session:
        return render_template('publicApplications.html', department=department,
            apps = apps)
    userID = login_session['user_id']
    if appsValue==True and department.user_id==userID:
        return render_template('newApp.html', department_id = department_id,
            department = department, appsValue=appsValue,
            userEmail=login_session['email'],
            userPicture=login_session['picture'])
    else:
        return render_template('applications.html', department=department,
            apps = apps, userEmail=login_session['email'],
            userPicture=login_session['picture'],
            loggedUser=login_session['user_id'])


@app.route('/department/<int:department_id>/App/<int:application_id>/')
def departmentAppsDesc(department_id, application_id):
    department = session.query(Department).filter_by(id = department_id).one()
    apps = session.query(Application).filter_by(id = application_id).one()
    if 'username' not in login_session:
        return render_template('publicApplicationDesc.html',
            department=department, apps=apps)
    else:
        return render_template('applicationDesc.html', department = department,
        apps = apps, userEmail=login_session['email'],
        userPicture=login_session['picture'])


@app.route('/allUsers')
def allUsers():
    allUser = session.query(User).all()
    if allUser == []:
        return redirect(url_for('showLogin'))
    admin = session.query(User).filter_by(id=1).one()
    if login_session['user_id'] != admin.id:
        flash("You are not the Admin")
        return redirect('departments')
    for i in allUser:
        print
    return render_template('allUsers.html', allUser = allUser,
        user_id=i.id, userEmail=login_session['email'],
        userPicture=login_session['picture'])


@app.route('/department/new/', methods=['GET', 'POST'])
def newDepartment():
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    if request.method == 'POST':
        newDepartment = Department(name = request.form['name'],
            user_id=login_session['user_id'])
        session.add(newDepartment)
        session.commit()
        flash("Item Created!")
        return redirect(url_for('departments'))
    else:
        return render_template('newDepartment.html',
            userEmail=login_session['email'],
            userPicture=login_session['picture'])


@app.route('/department/<int:department_id>/App/new/', methods=['GET', 'POST'])
def newApp(department_id):
    if 'username' not in login_session:
        return redirect('/login')
    department = session.query(Department).filter_by(id = department_id).one()
    userID = login_session['user_id']
    if department.user_id!=userID:
        flash("You are not the owner of this department...")
        return redirect(url_for('departmentApps',
            department_id = department_id))
    if request.method == 'POST':
        newApp = Application(name = request.form['name'],
            department_id = department_id, user_id=login_session['user_id'])
        session.add(newApp)
        session.commit()
        flash("App Created!")
        return redirect(url_for('departmentApps',
            department_id = department_id))
    else:
        return render_template('newApp.html', department_id = department_id,
            department = department,
            userEmail=login_session['email'],
            userPicture=login_session['picture'])


@app.route('/department/<int:department_id>/edit/',
           methods=['GET', 'POST'])
def editDepartment(department_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedDepartment = session.query(Department).filter_by(id=department_id).one()
    if login_session['user_id'] !=editedDepartment.user_id:
        flash("You are not the Department owner")
        return redirect('/departments')
    if request.method == 'POST':
        if request.form['name']:
            editedDepartment.name = request.form['name']
        session.add(editedDepartment)
        session.commit()
        flash("Item Updated!")
        return redirect(url_for('departments'))
    else:
        return render_template(
            'editDepartment.html', department_id=department_id,
            editDep = editedDepartment, userEmail=login_session['email'],
            userPicture=login_session['picture'])


@app.route('/department/<int:department_id>/App/<int:application_id>/edit/',
           methods=['GET', 'POST'])
def editApp(department_id, application_id):
    if 'username' not in login_session:
        return redirect('/login')
    department = session.query(Department).filter_by(id=department_id).one()
    editedApp = session.query(Application).filter_by(id=application_id).one()
    if login_session['user_id'] != department.user_id:
        flash("You are not the Department owner")
        return redirect('/departments')
    if request.method == 'POST':
        if request.form['name']:
            editedApp.name = request.form['name']
        if request.form['description']:
            editedApp.description = request.form['description']
        session.add(editedApp)
        session.commit()
        flash("App Updated!")
        return redirect(url_for('departmentApps',
            department_id = department_id))
    else:
        return render_template(
            'editApp.html', department_id=department_id,
            application_id=application_id, editedApp=editedApp,
            userEmail=login_session['email'],
            userPicture=login_session['picture'])


@app.route('/user/<int:user_id>/edit/',
           methods=['GET', 'POST'])
def editUser(user_id):
    if 'username' not in login_session:
        return redirect('/login')
    admin = session.query(User).filter_by(id=1).one()
    editedUser = session.query(User).filter_by(id=user_id).one()
    if login_session['user_id'] != admin.id:
        flash("You are not the Admin")
        return redirect('departments')
    if request.method == 'POST':
        if request.form['name']:
            editedUser.name = request.form['name']
        if request.form['email']:
            editedUser.email = request.form['email']
        session.add(editedUser)
        session.commit()
        flash("User Updated!")
        return redirect(url_for('allUsers'))
    else:
        return render_template(
            'editUser.html', user_id=user_id, editUser = editedUser,
            userEmail=login_session['email'],
            userPicture=login_session['picture'])


@app.route('/department/<int:department_id>/delete/', methods = ['GET', 'POST'])
def deleteDepartment(department_id):
    if 'username' not in login_session:
        return redirect('/login')
    departmentToDelete = session.query(Department).filter_by(id=department_id).one()
    appsToDelete = session.query(Application).filter_by(department_id=department_id).all()
    if login_session['user_id'] != departmentToDelete.user_id:
        flash("You are not the Department owner")
        return redirect('/departments')
    if request.method == 'POST':
        for i in appsToDelete:
            deleteApp(i.department_id, i.id)
        session.delete(departmentToDelete)
        session.commit()
        flash("Item deleted...")
        return redirect(url_for('departments'))
    else:
        return render_template('deleteDepartment.html',
            i = departmentToDelete, userEmail=login_session['email'],
            userPicture=login_session['picture'])


@app.route('/department/<int:department_id>/App/<int:application_id>/delete/',
    methods = ['GET', 'POST'])
def deleteApp(department_id, application_id):
    if 'username' not in login_session:
        return redirect('/login')
    appToDelete = session.query(Application).filter_by(id=application_id).one()
    if login_session['user_id'] != appToDelete.user_id:
        flash("You are not the Department owner")
        return redirect('/departments')
    if request.method == 'POST':
        session.delete(appToDelete)
        session.commit()
        flash("Item deleted...")
        return redirect(url_for('departmentApps',
            department_id = department_id))
    else:
        return render_template('deleteApp.html', department_id=department_id,
            application_id=application_id, i = appToDelete,
            userEmail=login_session['email'],
            userPicture=login_session['picture'])


@app.route('/user/<int:user_id>/delete/', methods = ['GET', 'POST'])
def deleteUser(user_id):
    admin = session.query(User).filter_by(id=1).one()
    userToDelete = session.query(User).filter_by(id=user_id).one()
    depsToDelete = session.query(Department).filter_by(user_id=user_id).all()
    if login_session['user_id'] != admin.id:
        flash("You are not the Admin")
        return redirect('departments')
    if request.method == 'POST':
        for i in depsToDelete:
            deleteDepartment(i.id)
        session.delete(userToDelete)
        session.commit()
        flash("User deleted...")
        return redirect(url_for('allUsers'))
    else:
        return render_template('deleteUser.html', i = userToDelete,
            userEmail=login_session['email'],
            userPicture=login_session['picture'])


if __name__ == '__main__':
    app.secret_key = 'xUldotBaq77gzfaY95BDbR6g'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
