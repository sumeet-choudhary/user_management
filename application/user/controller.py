from application import mongo
from application.role.controller import get_role_by_id


def find_user(email):
    result = mongo.db.user_collection.find_one({"email": email})
    if result:
        role_id = result.get("role")
        if role_id:
            role = get_role_by_id(role_id)
            role["_id"] = str(role["_id"])
            result["role"] = role  # Replace the role ID with the role details

    return result


def update_verification(email):
    result = mongo.db.user_collection.update_one({"email": email}, {"$set": {"verified": True}})
    return result


def add_new_user(all_values):
    result = mongo.db.user_collection.insert_one(all_values)
    return result


def set_password(email, password):
    result = mongo.db.user_collection.update_one({"email": email}, {"$set": {"password": password}})
    return result

