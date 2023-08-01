from application import mongo

# COMPANY COLLECTIONS ###


def find_user(email):
    result = mongo.db.user_collection.find_one({"email": email})
    return result


def update_verification(email):
    result = mongo.db.user_collection.update_one({"email": email}, {"$set": {"verified": True}})
    return result


def add_new_user(all_values):
    result = mongo.db.user_collection.insert_one(all_values)
    return result


def reset_password(email, password):
    result = mongo.db.user_collection.update_one({"email": email}, {"$set": {"password": password}})
    return result


# USER COLLECTIONS ###

# def add_new_user(all_values):
#     result = mongo.db.user_collection.insert_one(all_values)
#     return result
#
# def update_new_pass(email, new_password):
#     result = mongo.db.user_collection.update_one({"email": email}, {"$set": {"password": new_password}})
#     return result
#
# def update_reset_password(email, reset_new_password):
#     result = mongo.db.user_collection.update_one({"email": email}, {"$set": {"password": reset_new_password}})
#     return result
#
# # def delete_user(email):
# #     result = mongo.db.my_collection.delete_one({"email": email})
# #     result = True if result.acknowledged else False
# #    return result
#
# def soft_delete(email):
#     result = mongo.db.user_collection.update_one({"email": email}, {"$set": {"verified": False}})
#     return result
