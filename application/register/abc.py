# class CompanyRegister(Resource):
#     def post(self):
#         try:
#             company_name = request.json.get("company_name", None)
#             company_email = request.json.get("company_email", None)
#             all_values = {"company_name": company_name, "company_email": company_email}
#
#             if company_name in [None, ""] or company_email in [None, ""]:
#                 return make_response(jsonify({"message": "Credentials Not Found"}), 200)
#             already_a_user = find_user(company_email)
#             if already_a_user:
#                 return make_response(jsonify({"message": "This company Already Exist"}), 200)
#             else:
#                 add_new_company(all_values)
#                 return make_response(jsonify({"message": "Registered successfully"}))
#         except Exception as e:
#             return make_response(jsonify({"error": str(e)}, 500))


# class AdminRegister(Resource):
#     def post(self):
#         try:
#             company_name = request.json.get("company_name", None)
#             email = request.json.get("email", None)
#             password = request.json.get("password", None).encode()
#             hash_password = bcrypt.hashpw(password, bcrypt.gensalt(8))
#             role = "Admin"
#             verified = False
#             all_values = {"company_name": company_name, "email": email, "password": hash_password, "role": role, "verified": verified}
#
#             if company_name in [None, ""] or email in [None, ""] or password in [None, ""]:
#                 return make_response(jsonify({"message": "Credentials Not Found"}), 200)
#
#             already_a_user = find_user(email)
#             if already_a_user:
#                 return make_response(jsonify({"message": "This User Already Exist"}), 200)
#
#             else:
#                 expire_token_time = datetime.now() + timedelta(minutes=15)
#                 expire_epoch_time = int(expire_token_time.timestamp())
#                 made_payload = {"email": email, "exp": expire_epoch_time}
#                 made_verification_token = jwt.encode(made_payload, "sumeet", algorithm="HS256")
#                 # print(made_verification_token)
#
#                 email_sender = "sumeetchoudhary777@gmail.com"
#                 email_sender_password = os.environ.get("EMAIL_SENDER_PASSWORD")
#                 email_receiver = email
#                 subject = "Dear user"
#                 body = f"Your verification link: " \
#                        f"http://127.0.0.1:5000/verification?token={made_verification_token}"
#
#                 em = EmailMessage()
#                 em["FROM"] = email_sender
#                 em["TO"] = email_receiver
#                 em["SUBJECT"] = subject
#                 em.set_content(body)
#
#                 with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
#                     smtp.login(email_sender, email_sender_password)
#                     smtp.sendmail(email_sender, email_receiver, em.as_string())
#
#                 if add_new_user(all_values):
#                     return make_response(jsonify({"message": "Registered successfully"}))
#                 else:
#                     return make_response(jsonify({"message": "Registered not successfully"}))
#
#         except Exception as e:
#             return make_response(jsonify({"error": str(e)}, 500))


# class AdminLogin(Resource):
#     def post(self):
#         try:
#             email = request.json.get("email", None)
#             password = request.json.get("password", None).encode()
#             if email:
#                 already_in_db = find_user(email)
#                 verified = already_in_db["verified"]
#                 if verified:
#                     if already_in_db is None:
#                         return make_response(jsonify({"message": "This email doesn't exists"}), 200)
#                     if email == already_in_db["email"] and bcrypt.checkpw(password, already_in_db["password"]):
#                         access_token = create_access_token(identity=email, expires_delta=timedelta(minutes=15))
#                         refresh_token = create_refresh_token(identity=email, expires_delta=timedelta(days=1))
#                         return make_response(jsonify({"message": "you have login successfully",
#                                                       "Permissions": "you have all permissions as you're Admin!",
#                                                       "access_token": access_token,
#                                                       "refresh_token": refresh_token}), 200)
#                     else:
#                         return make_response(jsonify({"message": "wrong credentials, you can try changing password if you have forgotten"}), 500)
#                 else:
#                     return make_response(jsonify({"message": "first verify the email"}))
#         except Exception as e:
#             return make_response(jsonify({'error': str(e)}))


# class UpdatePassword(Resource):
#     @jwt_required()
#     def post(self):
#         try:
#             email_from_token = get_jwt_identity()
#             old_password = request.json.get("old_password", None).encode()
#             new_password = request.json.get("new_password", None).encode()
#             new_hash_password = bcrypt.hashpw(new_password, bcrypt.gensalt(8))
#
#             already_in_db = find_user(email_from_token)
#             password_in_db = already_in_db["password"]
#
#             if bcrypt.checkpw(old_password, password_in_db):
#                 update_new_pass(email_from_token, new_hash_password)
#                 return make_response(jsonify({"message": "new password has been set"}))
#             else:
#                 return make_response(jsonify({"message": "entered old password doesnt match"}))
#         except Exception as e:
#             return make_response(jsonify({"error": str(e)}))
#
#
# class ForgotPassword(Resource):
#     def post(self):
#         try:
#             email = request.json.get("email", None)
#             already_in_db = find_user(email)
#             verified = already_in_db["verified"]
#
#             if verified is True:
#                 if email == already_in_db["email"]:
#                     expire_token_time = datetime.now() + timedelta(minutes=15)
#                     expire_epoch_time = int(expire_token_time.timestamp())
#                     made_payload = {"email": email, "exp": expire_epoch_time}
#                     made_verification_token = jwt.encode(made_payload, "sumeet", algorithm="HS256")
#
#                     email_sender = "sumeetchoudhary777@gmail.com"
#                     email_sender_password = os.environ.get("EMAIL_PASSWORD")
#                     email_receiver = email
#                     subject = "Forgot Password"
#                     body = f"Your forgot password link: {made_verification_token}"
#
#                     em = EmailMessage()
#                     em["FROM"] = email_sender
#                     em["TO"] = email_receiver
#                     em["SUBJECT"] = subject
#                     em.set_content(body)
#
#                     with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
#                         smtp.login(email_sender, email_sender_password)
#                         smtp.sendmail(email_sender, email_receiver, em.as_string())
#
#                     return make_response(jsonify({"message": "an email has been sent to reset password"}))
#                 else:
#                     return make_response(jsonify({"message": "wrong email"}))
#             return make_response(jsonify({"message": "to reset the password, first you have to be a verified user"}))
#         except Exception as e:
#             return make_response(jsonify({"error": str(e)}))
#
#
# class ResetPassword(Resource):
#     def post(self):
#         try:
#             forgot_pass_email_token = request.json.get("token")
#             reset_new_password = request.json.get("reset_password", None).encode()
#             hashed_reset_new_password = bcrypt.hashpw(reset_new_password, bcrypt.gensalt(8))
#
#             if forgot_pass_email_token:
#                 token_decoded = jwt.decode(forgot_pass_email_token, "sumeet", algorithms=["HS256"])
#                 email = token_decoded["email"]
#                 already_in_db = find_user(email)
#                 verified = already_in_db["verified"]
#
#                 if verified is True:
#                     if email == already_in_db["email"]:
#                         update_reset_password(email, hashed_reset_new_password)
#                         return make_response(jsonify({"message": "new reset-password has been set"}))
#                     else:
#                         return make_response(jsonify({"message": "wrong email"}))
#                 return make_response(jsonify({"message": "to reset the password, first you have to be a verified user"}))
#
#         except Exception as e:
#             return make_response(jsonify({"message": str(e)}))
#
#
# class NewUser(Resource):
#     def post(self):
#         try:
#             # email_from_token = get_jwt_identity()
#             # already_in_db = find_user(email_from_token)
#             email = request.json.get("email")
#             password = request.json.get("password")
#             already_in_db = find_user(email)
#             if already_in_db["role"] == "Admin":
#                 if not already_in_db:
#                     return make_response(jsonify({"message": "user not found"}))


# class DeleteUser(Resource):
#     @jwt_required()
#     def post(self):
#         try:
#             email_from_token = get_jwt_identity()
#             already_in_db = find_user(email_from_token)
#
#             if already_in_db["role"] == "Admin":
#                 if not already_in_db:
#                     return make_response(jsonify({"message": "user not found"}))
#                 else:
#                     result = soft_delete(email_from_token)
#                     if result:
#                         return make_response(jsonify({"message": "user deleted successfully"}))
#             else:
#                 return make_response(jsonify({"message": "Only Admin have the permission to delete accounts"}))
#         except Exception as e:
#
#             return make_response(jsonify({"error": str(e)}))
#
#
# class Default(Resource):
#     def get(self):
#         return make_response(jsonify({"message": "its running"}))
