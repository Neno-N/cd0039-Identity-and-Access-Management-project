import os
from turtle import title
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

'''
@DONE uncomment the following line to initialize the datbase
!! NOTE THIS WILL DROP ALL RECORDS AND START YOUR DB FROM SCRATCH
!! NOTE THIS MUST BE UNCOMMENTED ON FIRST RUN
!! Running this funciton will add one
'''
db_drop_and_create_all()

# ROUTES
'''
@DONE implement endpoint
    GET /drinks
        it should be a public endpoint
        it should contain only the drink.short() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks', methods=['GET'])
def get_drinks():
    try:
        drinks = Drink.query.order_by(Drink.id).all()
        print('here')
        drinks_retrieved = [drink.short() for drink in drinks]
        if len(drinks_retrieved) == 0:
            abort(404)
        print('here now!')
    
        return jsonify({
            'success': True,
            'drinks': drinks_retrieved
             })
    except:
        abort(422)


'''
@DONE implement endpoint
    GET /drinks-detail
        it should require the 'get:drinks-detail' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks-detail', methods=['GET'])
@requires_auth('get:drinks-detail')
def get_detailed_drinks(payload):
    try:
        drinks = Drink.query.order_by(Drink.id).all()
        drinks_retrieved = [drink.long() for drink in drinks]
        if len(drinks_retrieved) == 0:
            print('api.py line 63 error')
            abort(404)
    
        return jsonify({
            'success': True,
            'drinks': drinks_retrieved
             })
    except:
        print('api.py line 71 error')
        abort(422)


'''
@DONE implement endpoint
    POST /drinks
        it should create a new row in the drinks table
        it should require the 'post:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the newly created drink
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def add_drink(payload):
    form = request.get_json()
    new_title = form.get('title')
    new_recipe = form.get('recipe')
    print(new_title, new_recipe)

    try:
        drink = Drink(title=new_title, recipe=json.dumps(new_recipe))
        print(drink)
        drink.insert()
        drink_inserted = [drink.long()]
        return jsonify({
            "success": True,
            "drinks": drink_inserted
        })
    except:
        print('api.py error line 104')
        abort(422)


'''
@DONE implement endpoint
    PATCH /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should update the corresponding row for <id>
        it should require the 'patch:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the updated drink
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks/<id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def edit_drink(payload, id):
    form = request.get_json()
    
    try:
        drink = Drink.query.filter(Drink.id == id).one_or_none()
        if drink is None:
            abort(404)

        if 'recipe' in form:
            recipe = form.get('recipe')
            drink.recipe = recipe
            drink.update()
            drink_updated = [drink.long()]

        if 'title' in form:
            title = form.get('title')
            drink.title = title
            drink.update()
            drink_updated = [drink.long()]
        

        return jsonify({
            "success": True,
            "drinks": drink_updated
        })
    except: 
        abort(422)
    


'''
@DONE implement endpoint
    DELETE /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should delete the corresponding row for <id>
        it should require the 'delete:drinks' permission
    returns status code 200 and json {"success": True, "delete": id} where id is the id of the deleted record
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks/<id>', methods=['DELETE'])
@requires_auth('delete:drinks')
def delete_drink(payload, id):
    try:
        drink = Drink.query.filter(Drink.id == id).one_or_none()
        if drink is None:
            abort(404)
        
        drink.delete()
        return jsonify({
            "success": True,
            "delete": id
        })
    except:
        abort(422)
    


# Error Handling
'''
Example error handling for unprocessable entity
'''


@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
    }), 422


'''
@DONE implement error handlers using the @app.errorhandler(error) decorator
    each error handler should return (with approprate messages):
             jsonify({
                    "success": False,
                    "error": 404,
                    "message": "resource not found"
                    }), 404

'''
@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        "success": False,
        "error": 400,
        "message": "bad request"
    }), 400

@app.errorhandler(405)
def not_allowed(error):
    return jsonify({
        "success": False,
        "error": 405,
        "message": "method not allowed"
    }), 405

'''
@DONE implement error handler for 404
    error handler should conform to general task above
'''
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "resource not found"
    }), 404

'''
@DONE implement error handler for AuthError
    error handler should conform to general task above
'''
@app.errorhandler(401)
def not_authorised(error):
    raise AuthError({
                'error': 401,
                'message': 'Unauthorised'
            }, 401)

@app.errorhandler(403)
def forbidden(error):
    raise AuthError({
                'error': 403,
                'message': 'Forbidden'
            }, 403)
