import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

db_drop_and_create_all()

# ROUTES
@app.route('/drinks')
def get_drinks():
    drinks = Drink.query.order_by(Drink.id).all()
    drinks_short = [drink.short() for drink in drinks]

    return jsonify({
        "success": True,
        "drinks": drinks_short,
    })


@app.route('/drinks-detail')
@requires_auth('get:drinks-detail')
def get_drink_details(payload):
    drinks = Drink.query.order_by(Drink.id).all()
    drinks_long = [drink.long() for drink in drinks]

    return jsonify({
        "success": True,
        "drinks": drinks_long,
    })


@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def create_drink(payload):
    body = request.get_json()
    try:
        drink = Drink(
            title=body.get('title', None),
            recipe=json.dumps(body.get('recipe', None)),
        )
        drink.insert()

        return jsonify({
            "success": True,
            "drinks": [drink.long()],
        })

    except BaseException:
        abort(422)


@app.route('/drinks/<int:id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def update_drink(payload, id):
    if id is None:
        abort(404)

    body = request.get_json()

    try:
        drink = Drink.query.filter(Drink.id == id).one_or_none()
        drink.title = body.get('title', None)
        drink.recipe = json.dumps(body.get('recipe', None))
        drink.update()

        return jsonify({
            "success": True,
            "drinks": [drink.long()]
        })
    except BaseException:
        abort(404)


@app.route('/drinks/<int:id>', methods=['DELETE'])
@requires_auth('delete:drinks')
def delete_drink(payload, id):
    if id is None:
        abort(404)

    try:
        drink = Drink.query.filter(Drink.id == id).one_or_none()
        drink.delete()

        return jsonify({
            "success": True,
            "delete": id,
        })
    except BaseException:
        abort(404)


# Error Handling
@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
    }), 422


@app.errorhandler(404)
def bad_request(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "resource not found"
    }), 404


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    return jsonify({
        "success": False,
        "error": ex.error['code'],
        "message": ex.error['description']
    }), ex.status_code
