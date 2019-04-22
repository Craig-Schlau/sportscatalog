from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import flash
from sqlalchemy import create_engine, asc, collate
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Sports, SportsItem, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

APP_PATH = '/var/www/sportscatalog'
CLIENT_ID = json.loads(
    open(APP_PATH + 'client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Sports Catalog App"

"""Connect to Database and create database session"""
engine = create_engine('sqlite:///sportscatalog.db?check_same_thread=False')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    """This def joins the login session"""
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    """return "The current session state is %s" % login_session['state']"""
    return render_template('login.html', STATE=state)


# Connect to the Google Sign-in oAuth method.
@app.route('/gconnect', methods=['POST'])
def gconnect():
    """This def is used to validate the login"""
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    """Obtain authorization code"""
    code = request.data

    try:
        """Upgrade the authorization code into a credentials object"""
        oauth_flow = flow_from_clientsecrets(APP_PATH + 'client_secrets.json',
                                             scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    """Check that the access token is valid."""
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    """If there was an error in the access token info, abort."""
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    """Verify that the access token is used for the intended user."""
    google_id = credentials.id_token['sub']
    if result['user_id'] != google_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    """Verify that the access token is valid for this app."""
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_google_id = login_session.get('google_id')
    if stored_access_token is not None and google_id == stored_google_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    """Store the access token in the session for later use."""
    login_session['access_token'] = credentials.access_token
    login_session['google_id'] = google_id

    """Get user info."""
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    """Assign email address as name if User does not have Google"""
    if "name" in data:
        login_session['username'] = data['name']
    else:
        name_corp = data['email'][:data['email'].find("@")]
        login_session['username'] = name_corp
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    """See if the user exists. If it doesn't, make a new one."""
    user_id = getUserId(data["email"])

    # If user_id = None
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    """Show a welcome screen upon successful login."""
    output = ''
    output += '<h2>Welcome, '
    output += login_session['username']
    output += '!</h2>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px; '
    output += 'border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;">'
    flash("You are now logged in as %s!" % login_session['username'])
    print("Done!")
    return output


# Disconnect Google Account.
def gdisconnect():
    """Disconnect the Google account of the current logged-in user."""

    # Only disconnect the connected user.
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
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Log out the currently connected user.
@app.route('/logout')
def logout():
    """Log out the currently connected user."""

    if 'username' in login_session:
        gdisconnect()
        del login_session['google_id']
        del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        flash("You have been successfully logged out!")
        return render_template('sports.html')
    else:
        flash("You were not logged in!")
        return render_template('sports.html')


# Create new user.
def create_user(login_session):
    """Crate a new user.
    Argument:
    login_session (dict): The login session.
    """

    new_user = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture']
    )
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """Get user information by ID.
    Argument:
        user_id (int): The user ID.
    Returns:
        The user's details.
    """

    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserId(email):
    """Get user ID by email.
    Argument:
        email (str) : the email of the user.
    """

    try:
        user = session.query(User).filter_by(email=email).one()

        return user.id
    except BaseException:
        return None


# JSON APIs to view Sports Information
@app.route('/sports/<int:sports_id>/items/JSON')
def sportsitemJSON(sports_id):
    """This def will query Sports and SportsItem and filter the results"""
    sports = session.query(Sports).filter_by(id=sports_id).one()
    items = session.query(SportsItem).filter_by(
        sports_id=sports_id).all()
    return jsonify(SportsItems=[i.serialize for i in items])


@app.route('/sports/<int:sports_id>/items/<int:items_id>/JSON')
def SportItemJSON(sports_id, items_id):
    """This def querys SportsItems and filters by items and sports ids"""
    SportItem = session.query(SportsItem).filter_by(id=items_id).filter_by(
                                sports_id=sports_id).one()
    return jsonify(SportItem=SportItem.serialize)


@app.route('/sports/JSON')
def sportsJSON():
    """This def will show all sports in the database"""
    sports = session.query(Sports).all()
    return jsonify(sports=[s.serialize for s in sports])


# Show all sports
@app.route('/')
@app.route('/sports/')
def showSports():
    """This query will show all sports in asc order"""
    sports = session.query(Sports).order_by(asc(collate(Sports.name,
                                                        'NOCASE')))
    return render_template('sports.html', sports=sports)


# Create a new sport
@app.route('/sports/new/', methods=['GET', 'POST'])
def newSports():
    """This def will check the user and create
       a new sport under the username"""
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newSports = Sports(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newSports)
        flash('New Sport %s Successfully Created' % newSports.name)
        session.commit()
        return redirect(url_for('showSports'))
    else:
        return render_template('newSports.html')


# Edit a sport
@app.route('/sports/<int:sports_id>/edit/', methods=['GET', 'POST'])
def editSports(sports_id):
    editedSports = session.query(
        Sports).filter_by(id=sports_id).one()
    """Verifies user is allowed to edit the sport"""
    if 'username' not in login_session:
        return redirect('/login')
    if editedSports.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized" \
               " to edit this sport. Please create your own sport in order " \
               "to edit.');window.location.replace('/sports/');}" \
               "</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedSports.name = request.form['name']
            return redirect(url_for('showSports'))
    else:
        return render_template('editSports.html', sports=editedSports)


# Delete a sport
@app.route('/sports/<int:sports_id>/delete/', methods=['GET', 'POST'])
def deleteSports(sports_id):
    sportsToDelete = session.query(
        Sports).filter_by(id=sports_id).one()
    """Verifies if user is allowed to delete a sport"""
    if 'username' not in login_session:
        return redirect('/login')
    if sportsToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized" \
               " to delete this sport. Please create your own sport in order" \
               " to delete.');window.location.replace('/sports/');}" \
               "</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(sportsToDelete)
        session.commit()
        return redirect(url_for('showSports', sports_id=sports_id))
    else:
        return render_template('deleteSports.html', sports=sportsToDelete)


# Show a sports item
@app.route('/sports/<int:sports_id>/')
@app.route('/sports/<int:sports_id>/items/')
def showSportsItem(sports_id):

    """Shows sports items and who created them"""
    sports = session.query(Sports).filter_by(id=sports_id).one()

    creator = getUserInfo(sports.user_id)

    items = session.query(User, SportsItem).filter(
        User.id == SportsItem.user_id).filter(
        SportsItem.sports_id == sports_id).order_by(
        asc(collate(SportsItem.name, 'NOCASE'))).all()

    if 'username' not in login_session:
        return render_template(
            'sportsitems.html',
            items=items,
            sports=sports,
            creator=creator,
            loggedin="no")

    if 'username' not in login_session != login_session['user_id']:
        return render_template(
            'sportsitems.html',
            items=items,
            sports=sports,
            creator=creator,
            loggedin="no")
    else:
        return render_template(
            'sportsitems.html',
            items=items,
            sports=sports,
            creator=creator,
            loggedin="yes")


# Create a new sports item
@app.route('/sports/<int:sports_id>/items/new/', methods=['GET', 'POST'])
def newSportsItem(sports_id):
    """Verifies user is logged in before creating a new item"""
    if 'username' not in login_session:
        return redirect('/login')
    sports = session.query(Sports).filter_by(id=sports_id).one()
    # if login_session['user_id'] != sports.user_id:
    if 'username' not in login_session:
        return redirect('/login')
    elif request.method == 'POST':
        newSportsItem = SportsItem(
            name=request.form['name'],
            description=request.form['description'],
            sports_id=sports_id,
            user_id=login_session['user_id'])
        session.add(newSportsItem)
        session.commit()
        flash('New Sports Item %s Successfully Created' % newSportsItem.name)
        return redirect(url_for('showSportsItem', sports_id=sports_id))
    else:
        return render_template(
            'newsportsitems.html',
            sports_id=sports_id,
            sports=sports)


# Edit a sports item
@app.route(
    '/sports/<int:sports_id>/items/<int:items_id>/edit',
    methods=[
        'GET',
        'POST'])
def editSportsItem(sports_id, items_id):
    """Verifies the user is allowed to edit the item"""
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(SportsItem).filter_by(id=items_id).one()
    sports = session.query(Sports).filter_by(id=sports_id).one()
    if login_session['user_id'] != editedItem.user_id:
        return "<script>function myFunction() {alert('You are not " \
               "authorized to edit this item. Please create" \
               " your own sports item in order to edit.');" \
               "window.location.replace('/sports/" +\
               str(sports_id) + "/items/');}</script><body onload=" \
                                "'myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        return redirect(url_for('showSportsItem', sports_id=sports_id))
    else:
        return render_template(
            'editsportsitems.html',
            sports_id=sports_id,
            items_id=items_id,
            item=editedItem)


# Delete a sports item


@app.route(
    '/sports/<int:sports_id>/items/<int:items_id>/delete',
    methods=[
        'GET',
        'POST'])
def deleteSportsItem(sports_id, items_id):
    """Verifies the user is allowed to delete the item"""
    if 'username' not in login_session:
        return redirect('/login')
    deleteItem = session.query(SportsItem).filter_by(id=items_id).one()
    sports = session.query(Sports).filter_by(id=sports_id).one()
    if login_session['user_id'] != deleteItem.user_id:
        return "<script>function myFunction() {alert('You are not " \
               "authorized to delete this item. Please " \
               "create your own sports item in order to delete.')" \
               ";window.location.replace('/sports/" +\
               str(sports_id) + "/items/');}" \
               "</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(deleteItem)
        session.commit()
        return redirect(url_for('showSportsItem', sports_id=sports_id))
    else:
        return render_template('deleteSportsItems.html', item=deleteItem)


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
            del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showSports'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showSports'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
app.run(host='18.218.24.9', port=80)
