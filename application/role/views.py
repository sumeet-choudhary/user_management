from flask import Blueprint, request, make_response, jsonify
from flask_restful import Resource
from application import api
from dotenv import load_dotenv
from flask_jwt_extended import jwt_required, get_jwt_identity
from application.role.controller import find_role, add_new_role, update_role
from application.user.controller import find_user


load_dotenv()
role_blueprint = Blueprint("role_blueprint", __name__)


class AddRole(Resource):
    """This api is used to add new roles with specified permissions to those roles"""
    @jwt_required()
    def post(self):
        try:
            admin_email = get_jwt_identity()
            name = request.json.get("name", None)
            permissions = request.json.get("permissions", None)

            all_values = {"name": name, "permissions": permissions}

            if name in [None, ""] or permissions in [None, ""]:
                return make_response(jsonify({"message": "Credentials Missing"}), 500)

            already_user = find_user(admin_email)
            if not already_user:
                return make_response(jsonify({"message": "User with provided email does not exist."}), 500)

            if already_user["role"]["name"] != "Admin":
                return make_response(jsonify({"message": "Only Admin can add new roles"}), 500)

            already_role = find_role(name)
            if already_role:
                return make_response(jsonify({"message": "Role with given name already exist"}), 500)

            if add_new_role(all_values):
                return make_response(jsonify({"message": "Role added successfully."}), 200)

            else:
                return make_response(jsonify({"message": "Error adding role"}), 500)

        except Exception as e:
            return make_response(jsonify({"error": str(e)}, 500))


class UpdateRole(Resource):
    """This api is used to update the role and permissions of that role"""
    @jwt_required()
    def put(self, name):
        try:
            admin_email = get_jwt_identity()
            new_name = request.json.get("name", None)
            permissions = request.json.get("permissions", None)

            all_values = {"name": new_name, "permissions": permissions}

            if name in [None, ""] or permissions in [None, ""] or new_name in [None, ""]:
                return make_response(jsonify({"message": "Credentials Missing"}), 500)

            already_user = find_user(admin_email)

            if name == "Admin":
                return make_response(jsonify({"message": "Admin role can't be updated."}), 500)

            if not already_user:
                return make_response(jsonify({"message": "User with provided email does not exist."}), 500)

            if already_user["role"]["name"] != "Admin":
                return make_response(jsonify({"message": "Only Admin can update roles"}), 500)

            already_role = find_role(name)
            if not already_role:
                return make_response(
                    jsonify({"message": "Old role name that you are trying to update does not exist."}), 500)

            already_role_new = find_role(new_name)
            if already_role_new:
                return make_response(jsonify({"message": "New role name that you are trying to update already exist. "
                                                         "Try with another name"}), 500)

            if update_role(name, all_values):
                return make_response(make_response({"message": "Role updated successfully"}), 200)

            else:
                return make_response(jsonify({"message": "Error updated role"}), 500)

        except Exception as e:
            return make_response(jsonify({"error": str(e)}, 500))


api.add_resource(AddRole, "/role")
api.add_resource(UpdateRole, "/role/<string:name>")
