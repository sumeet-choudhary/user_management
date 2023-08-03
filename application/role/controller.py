from flask import make_response, jsonify
from application import mongo

"""" ROLE COLLECTIONS """


def find_role(name):
    try:
        result = mongo.db.role_collection.find_one({"name": name})
        return result
    except Exception as e:
        return make_response(jsonify({"error": str(e)}))


def update_role(old_name, all_values):
    try:
        result = mongo.db.role_collection.update_one({"name": old_name}, {"$set": all_values})
        return result
    except Exception as e:
        return make_response(jsonify({"error": str(e)}))


def add_new_role(all_values):
    try:
        result = mongo.db.role_collection.insert_one(all_values)
        return result
    except Exception as e:
        return make_response(jsonify({"error": str(e)}))


def get_role_by_id(role_id):
    try:
        result = mongo.db.role_collection.find_one({"_id": role_id})
        return result
    except Exception as e:
        return make_response(jsonify({"error": str(e)}))