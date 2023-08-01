from application.register.views import register_blueprint
from application import app

app.register_blueprint(register_blueprint)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")

