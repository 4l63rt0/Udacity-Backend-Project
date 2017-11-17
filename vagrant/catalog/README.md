#Item Catalog Project

##About

This is a Udacity - Full Stack Web Developemt Project (Item Catalog) created to practice the use of Python, SQLAlchemy, Flask, OAuth2, API's, HTML, and CSS.

The main idea for this project was to learn how to develop a RESTful web application using the Python framework Flask along with implementing third-party OAuth authentication.

##Dependencies

- Udacity Vagrant File
- Python 2.7.12
- VirtualBox 5.1.28
- Vagrant 1.9.6
- GitBash 2.14.2

##Using Google Login

To get the Google login working there are a few additional steps:

Go to Google Dev Console
Sign up or Login if prompted
Go to Credentials
Select Create Crendentials > OAuth Client ID
Select Web application
Enter name 'Item-Catalog'
Authorized JavaScript origins = 'http://localhost:8000'
Authorized redirect URIs = 'http://localhost:8000/login' && 'http://localhost:8000/gconnect'
Select Create
Copy the Client ID and paste it into the data-clientid in login.html
On the Dev Console Select Download JSON
Rename JSON file to client_secrets.json
Place JSON file in item-catalog directory that you cloned from here
Run application using python
JSON Endpoints

##The following are open to the public:

List of all available departments:
<code>"/deparments/JSON"</code>

List of applications depending on department:
<code>"/department/<int:department_id>/JSON"</code>

App description:
<code>"/department/<int:department_id>/App/<int:application_id>/JSON"</code>
