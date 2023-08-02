from application import mongo

# ROLE COLLECTIONS #


def find_role(name):
    result = mongo.db.role_collection.find_one({"name": name})
    return result


def update_role(old_name, all_values):
    result = mongo.db.role_collection.update_one({"name": old_name}, {"$set": all_values})
    return result


def add_new_role(all_values):
    result = mongo.db.role_collection.insert_one(all_values)
    return result


def get_role_by_id(role_id):
    result = mongo.db.role_collection.find_one({"_id": role_id})
    return result
