from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response, flash
from flask import session as login_session
import random
import string
import json
from sqlalchemy import create_engine, desc
from sqlalchemy.pool import SingletonThreadPool
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
import httplib2
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

engine = create_engine('sqlite:///catalogapp.db',
                       poolclass=SingletonThreadPool)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# login route


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


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
        print("Token's client ID does not match app's.")
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

    if session.query(User).filter_by(email=data['email']).count() != 0:
        current_user = session.query(User).filter_by(email=data['email']).one()
    else:
        newUser = User(name=data['name'],
                       email=data['email'])
        session.add(newUser)
        session.commit()
        current_user = newUser

    login_session['user_id'] = current_user.id
    print(current_user.id)

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return output

# to disconnect after logging


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    print("token is ")
    print(access_token)
    print("this")
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print('In gdisconnect access token is %s', access_token)
    print('User name is: ')
    print(login_session['username'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('url is ' + url)
    print('result is ')
    print(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash("Successfully logged out")
        return redirect('/')
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

# Home page


@app.route('/')
def MainPage():
    categories = session.query(Category).all()
    itemslist = session.query(Item).order_by(desc(Item.id)).all()
    return render_template('cataloglist.html', categories=categories, itemslist=itemslist, username='username', login_session=login_session)


# To show items of current category
@app.route('/catalog/<string:categoryName>/items')
def ListCategoryItems(categoryName):
    categories = session.query(Category).all()
    CCategory = session.query(Category).filter_by(name=categoryName).first()
    itemslist = session.query(Item).filter_by(categoryName=CCategory.name)
    return render_template('CurrentCategoryItemlist.html', CurrentCategory=CCategory, itemslist=itemslist, categories=categories, username='username', login_session=login_session)

# To show details of a particular item


@app.route('/catalog/<string:ccategoryName>/<string:item>')
def ItemDetail(ccategoryName, item):
    CCategory = session.query(Category).filter_by(name=ccategoryName).first()
    citem = session.query(Item).filter_by(
        categoryName=CCategory.name, title=item).first()
    return render_template('ItemDetail.html', Currentitem=citem, CCategory=CCategory, login_session=login_session, username='username')

# To add new Category


@app.route('/addcategory', methods=['POST', 'GET'])
def AddCategory():

    if 'username' not in login_session:
        return redirect('/login')

    user_id = login_session['user_id']

    if request.method == 'POST':
        newCategory = Category(name=request.form['name'], user_id=user_id)
        session.add(newCategory)
        session.commit()
        return redirect(url_for('MainPage'))
    else:
        return render_template('NewCategory.html', username='username', login_session=login_session)


# To add new Item to a Category
@app.route('/additems', methods=['POST', 'GET'])
def AddItems():
    if 'username' not in login_session:
        return redirect('/login')

    user_id = login_session['user_id']

    if request.method == 'POST':
        ccategory = session.query(Category).filter_by(
            name=request.form['category']).first()
        newItem = Item(title=request.form['name'],
                       description=request.form['description'], category=ccategory, user_id=user_id)
        session.add(newItem)
        session.commit()
        return redirect(url_for('MainPage'))
        # return request.form['category']
    else:
        categories = session.query(Category).all()
        return render_template('NewItem.html', categories=categories, username='username', login_session=login_session)

# To update an existing Item


@app.route('/catalog/<string:categoryname>/<string:itemname>/edit', methods=['POST', 'GET'])
def UpdateItems(categoryname, itemname):

    if 'username' not in login_session:
        return redirect('/login')

    ccategory = session.query(Category).filter_by(
        name=categoryname).first()
    citem = session.query(Item).filter_by(
        categoryName=ccategory.name, title=itemname).first()

    if ccategory.user_id != login_session['user_id']:
        flash('Category was created by another user and can only be edited by creator')
        print("not allowed")
        return redirect(url_for('ItemDetail', ccategoryName=citem.categoryName, item=citem.title))

    if request.method == 'POST':
        if request.form['name']:
            citem.title = request.form['name']
        if request.form['description']:
            citem.description = request.form['description']
        if request.form['category']:
            ccategory = session.query(Category).filter_by(
                name=request.form['category']).first()
            citem.category = ccategory
            citem.categoryName = ccategory.name
        session.add(citem)
        session.commit()
        return redirect(url_for('ItemDetail', ccategoryName=citem.categoryName, item=citem.title))
    else:
        categories = session.query(Category).all()
        return render_template('UpdateItem.html', item=citem, categoryname=categoryname, itemname=itemname, categories=categories, username='username', login_session=login_session)

# To delete an Item


@app.route('/catalog/<string:categoryname>/<string:itemname>/delete', methods=['POST', 'GET'])
def DeleteItems(categoryname, itemname):

    if 'username' not in login_session:
        return redirect('/login')

    citem = session.query(Item).filter_by(
        categoryName=categoryname, title=itemname).first()

    if citem.user_id != login_session['user_id']:
        flash('Item was added by another user and can only be deleted by creator')
        print("not allowed")
        return redirect(url_for('ItemDetail', ccategoryName=citem.categoryName, item=citem.title))

    if request.method == 'POST':
        session.delete(citem)
        session.commit()
        return redirect(url_for('ListCategoryItems', categoryName=categoryname))
    else:
        return render_template('DeleteItem.html', item=citem, username='username', login_session=login_session)


# Returns all categories in JSON
@app.route('/category/json')
def MainPageJson():
    categories = session.query(Category).all()
    return jsonify(Categories=[i.serialize for i in categories])


# Returns all Items in JSON
@app.route('/item/json')
def itemsJson():
    itemslist = session.query(Item).order_by(desc(Item.id)).all()
    return jsonify(Items=[i.serialize for i in itemslist])

# Give details of item in JSON


@app.route('/catalog/<string:ccategoryName>/<string:item>/json')
def ItemDetailJson(ccategoryName, item):
    citem = session.query(Item).filter_by(
        categoryName=ccategoryName, title=item).first()
    return jsonify(item=citem.serialize)

# Returns all Items of a category in JSON


@app.route('/catalog/<string:categoryName>/items/json')
def ListCategoryItemsJson(categoryName):
    itemslist = session.query(Item).filter_by(categoryName=categoryName)
    return jsonify(Items=[i.serialize for i in itemslist])


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
