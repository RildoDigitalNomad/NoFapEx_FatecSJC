from flask import Flask
from flask_restful import Api, Resource, reqparse
from config import Config
from flask_login import LoginManager
from flask_mongoengine import MongoEngine, Document
import json
import datetime
from flask_login import UserMixin
from flask_jwt_extended import JWTManager
from flask_cors import CORS, cross_origin


app = Flask(__name__)

app.config['MONGODB_SETTINGS'] = {
    'db': 'project1',
    'host': 'mongodb://localhost/database_name'
}
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
db = MongoEngine(app)
app.config.from_object(Config)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
jwt = JWTManager(app)
api = Api(app, prefix="/temp/user")
cors = CORS(app, resources={r"/*": {"origins": "*"}})
app.config.update(PROPAGATE_EXCEPTIONS = True)

class User(UserMixin, db.Document):
    meta = {'collection': 'users'}
    username = db.StringField()
    email = db.StringField(max_length=150)
    password = db.StringField()

class User_Setting(db.EmbeddedDocument):
    username = db.StringField()
    email = db.StringField(max_length=150)
    password = db.StringField()

class BrowserHistory (db.EmbeddedDocument):
    siteUrl = db.StringField()
    dataAcesso = db.DateTimeField()

class DeviceSettings (db.EmbeddedDocument):
	blockImgSugest = db.BooleanField()
	blockSiteSugest = db.BooleanField()
	blockImgPorn = db.BooleanField()
	blockImgNud = db.BooleanField()
	blockSitePorn = db.BooleanField()
	blockSiteNud = db.BooleanField()
	notifDesinst = db.BooleanField()
	modSilencioso = db.BooleanField()

class Devices(db.EmbeddedDocument):
    deviceAlias = db.StringField()
    deviceHash = db.StringField()
    deviceSetting = db.EmbeddedDocumentField(DeviceSettings)
    browserHistory = db.ListField(db.EmbeddedDocumentField(BrowserHistory))

class Conta(UserMixin, db.Document):
    meta = {'collection': 'contas'}
    createdDate = db.DateTimeField()
    userSetting = db.EmbeddedDocumentField(User_Setting)
    devices= db.ListField(db.EmbeddedDocumentField(Devices))

#---------------------------
class ModerationLabels (db.EmbeddedDocument):
    confidence = db.FloatField()
    name = db.StringField()
    parentName = db.StringField()

class ImgCache (db.Document):
    meta = {'collection': 'imgCache'}
    createdDate = db.DateTimeField()
    imgBase64 = db.BinaryField()
    imgUrl = db.StringField()
    moderationLabels = db.ListField(db.EmbeddedDocumentField(ModerationLabels))

#@jwt.user_claims_loader
#def add_claims_to_access_token(identity):
#    return {
#        'hello': identity,
#        'foo': ['bar', 'baz']
#    }


@login_manager.user_loader
def load_user(user_id):
    return Conta.objects(pk=user_id).first()


from app import routes
from app.controllers import *
from app.model import *

api.add_resource(routes.PrivateResource, '/private')
api.add_resource(routes.VerificaTokenValida, '/verificaTokenValida')
api.add_resource(routes.CreateNewDevice, '/createNewDevice')
