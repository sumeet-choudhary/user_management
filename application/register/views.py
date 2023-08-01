from flask import Blueprint, request, make_response, jsonify
from flask_restful import Resource
from application import api
from datetime import datetime, timedelta
import jwt
from dotenv import load_dotenv
import bcrypt
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from application.register.controller import add_new_user, find_user, update_verification, reset_password
from application.celery_config.celery_task import send_mail


load_dotenv()
register_blueprint = Blueprint("register_blueprint", __name__)


class UserRegister(Resource):
    def post(self):
        try:
            name = request.json.get("name", None)
            email = request.json.get("email", None)
            company_name = request.json.get("company_name", None)
            role = "Admin"
            verified = False
            all_values = {"name": name, "email": email, "role": role, "company_name": company_name,
                          "verified": verified}

            if name in [None, ""] or email in [None, ""] or company_name in [None, ""]:
                return make_response(jsonify({"message": "Credentials Missing"}), 200)

            already_user = find_user(email)
            if already_user:
                return make_response(jsonify({"message": "This User Already Exist"}), 200)

            else:
                expire_token_time = datetime.now() + timedelta(minutes=15)
                expire_epoch_time = int(expire_token_time.timestamp())
                made_payload = {"email": email, "exp": expire_epoch_time}
                made_verification_token = jwt.encode(made_payload, "sumeet", algorithm="HS256")

                if add_new_user(all_values):
                    send_mail.delay(email, made_verification_token)
                    return make_response(jsonify({"message1": "Registered successfully",
                                                  "message2": "A mail has been sent to provided user email for verification"}))
                else:
                    return make_response(jsonify({"message": "Registered not successfully"}))

        except Exception as e:
            return make_response(jsonify({"error": str(e)}, 500))


class Verification(Resource):
    def get(self):
        try:
            token = request.args.get("token")
            if token:
                token_decoded = jwt.decode(token, "sumeet", algorithms=["HS256"])
                email = token_decoded["email"]
                already_user = find_user(email)
                if email == already_user["email"]:
                    update_verification(email)
                return make_response(jsonify({"message": "Your account is now Verified!"}))
        except Exception as e:
            return make_response(jsonify({"message": str(e)}))


class SetPassword(Resource):
    def post(self):
        try:
            email = request.json.get("email", None)
            password = request.json.get("password", None).encode()
            hash_password = bcrypt.hashpw(password, bcrypt.gensalt(8))

            if email in [None, ""] or password in [None, ""]:
                return make_response(jsonify({"message": "Credentials Missing"}))

            already_user = find_user(email)
            verified = already_user["verified"]

            if email == already_user["email"]:
                if verified:
                    reset_password(email, hash_password)
                    return make_response(jsonify({"message": "Password set successfully!"}))
                else:
                    return make_response(jsonify({"message": "Please verify your email first"}))
            else:
                return make_response(jsonify({"message": "Please Register first with this email"}))
        except Exception as e:
            return make_response(jsonify({"message": str(e)}))


class UserLogin(Resource):
    def post(self):
        try:
            email = request.json.get("email", None)
            print(email)
            password = request.json.get("password", None).encode()
            print(password)

            if email in [None, ""] or password in [None, ""]:
                return make_response(jsonify({"message": "Credentials Missing"}))

            if email:
                print(email)
                already_user = find_user(email)
                verified = already_user["verified"]

                if email != already_user["email"]:
                    print(email)
                    return make_response(jsonify({"message": "Register first with this email"}))
                if password not in already_user:
                    print(password)
                    return make_response(jsonify({"message": "First set your password before trying to login"}))
                if bcrypt.checkpw(password, already_user["password"]) is False:
                    return make_response(jsonify({"message": "Wrong Password"}))
                if verified:
                    if email == already_user["email"] and bcrypt.checkpw(password, already_user["password"]):
                        access_token = create_access_token(identity=email, expires_delta=timedelta(minutes=30))
                        refresh_token = create_refresh_token(identity=email, expires_delta=timedelta(days=1))
                        return make_response(jsonify({"message": "You have login successfully!",
                                                      "permissions": "You have all permissions as you're Admin!",
                                                      "access_token": access_token,
                                                      "refresh_token": refresh_token}), 200)
                else:
                    return make_response(jsonify({"message": "First verify the email"}))
        except Exception as e:
            return make_response(jsonify({'error': str(e)}))


class UserAdd(Resource):
    @jwt_required()
    def post(self):
        try:
            admin_email = get_jwt_identity()
            name = request.json.get("name", None)
            email = request.json.get("email", None)
            role = request.json.get("role", None)
            company_name = request.json.get("company_name", None)
            verified = False
            all_values = {"name": name, "email": email, "role": role, "company_name": company_name, "verified": verified}

            if name in [None, ""] or email in [None, ""] or role in [None, ""] or company_name in [None, ""]:
                return make_response(jsonify({"message": "Credentials Missing"}))

            already_user = find_user(admin_email)
            if already_user["role"] == "Admin":
                if not already_user:
                    return make_response(jsonify({"message": "Admin not found"}))
                else:
                    expire_token_time = datetime.now() + timedelta(minutes=15)
                    expire_epoch_time = int(expire_token_time.timestamp())
                    made_payload = {"email": email, "exp": expire_epoch_time}
                    made_verification_token = jwt.encode(made_payload, "sumeet", algorithm="HS256")

                    if add_new_user(all_values):
                        send_mail.delay(email, made_verification_token)
                        return make_response(jsonify({"message1": f"New user has been added successfully with {role} role",
                                                      "message2": "A mail has been sent to provided user email for verification"}))
            else:
                return make_response(jsonify({"message": "Only Admin can create new users"}))
        except Exception as e:
            return make_response(jsonify({"error": str(e)}))


api.add_resource(UserRegister, "/user/register")
api.add_resource(Verification, "/verification")
api.add_resource(SetPassword, "/user/set_password")
api.add_resource(UserLogin, "/user/login")
api.add_resource(UserAdd, "/add/new_user")
# api.add_resource(UpdatePassword, "/user/password/update")
# api.add_resource(ForgotPassword, "/user/forgot/password")
# api.add_resource(ResetPassword, "/user/reset/password")
# api.add_resource(DeleteUser, "/user/delete")
# api.add_resource(Default, "/")

