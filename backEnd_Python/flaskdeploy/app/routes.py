from flask import render_template, flash, redirect, url_for
from app import app, User, Conta, User_Setting, Devices, DeviceSettings, BrowserHistory, ImgCache, ModerationLabels
from app.forms import LoginForm
import logger
import os, sys
from flask_login import current_user, login_user, logout_user, login_required
from flask import jsonify, request, make_response, send_from_directory
from werkzeug.urls import url_parse
from app.forms import RegistrationForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_restful import Api, Resource, reqparse
import requests
import boto3
import botocore.session
from datetime import datetime, time, timedelta
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt, get_jwt_claims)
import json
import random

class PrivateResource(Resource):
    @jwt_required
    def get(self):
        return {"meaning_of_life": 42}

class VerificaTokenValida(Resource):
	@jwt_required
	def get(self):
		return {"msg": "Token ainda valida!"}


class CreateNewDevice(Resource):
	@jwt_required
	def post(self):
		print("Chegou no SV o metodo do CreateNew")
		hash = random.getrandbits(128)
		userToken = get_jwt_identity()
		accCheck = Conta.objects(userSetting__email = userToken)
		accFound = accCheck[0]
		newDevice = Devices()
		newDeviceSetting = DeviceSettings (False, False, False, False, False, False, False, False)
		newDevice.deviceAlias = "Pc do(a) " + accFound.userSetting.username + ' ' + str(len(accFound.devices) + 1)
		newDevice.deviceHash = str(hash)
		newDevice.deviceSetting = newDeviceSetting
		Conta.objects.filter(id = accFound.id).update(push__devices = newDevice)
		accFound.reload()
		deviceToReturn = findDeviceByHash(accCheck[0], str(hash))
		return make_response(jsonify({
			'deviceAlias': deviceToReturn.deviceAlias,
			'deviceHash': deviceToReturn.deviceHash,
			'blockImgSugest' : deviceToReturn.deviceSetting.blockImgSugest,
			'blockSiteSugest' :deviceToReturn.deviceSetting.blockSiteSugest,
			'blockImgPorn': deviceToReturn.deviceSetting.blockImgPorn,
			'blockImgNud' : deviceToReturn.deviceSetting.blockImgNud,
			'blockSitePorn' : deviceToReturn.deviceSetting.blockSitePorn,
			'blockSiteNud' : deviceToReturn.deviceSetting.blockSiteNud,
			'notifDesinst' : deviceToReturn.deviceSetting.notifDesinst,
			'modSilencioso' : deviceToReturn.deviceSetting.modSilencioso
		}))

ROOT_PATH = os.path.dirname(os.path.realpath(__file__))
os.environ.update({'ROOT_PATH': ROOT_PATH})
sys.path.append(os.path.join(ROOT_PATH, 'app'))

LOG = logger.get_root_logger(os.environ.get(
    'ROOT_LOGGER', 'root'), filename=os.path.join(ROOT_PATH, 'output.log'))





@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/')
@app.route('/index')
@login_required
def index():
    posts = [
        {
            'author': {'username': 'John'},
            'body': 'Beautiful day in Portland!'
        },
        {
            'author': {'username': 'Susan'},
            'body': 'The Avengers movie was so cool!'
        }
    ]
    return render_template('index.html', title='Home', posts=posts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    print("ENTROU LOGIN!!!")
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        if form.validate_on_submit():
            accCheck = Conta.objects(userSetting__email = form.username.data)
            if accCheck:
                if check_password_hash(accCheck[0].userSetting.password, form.password.data):
                    login_user(accCheck[0])
                    print("Passou pelo login??? " , accCheck[0])
                    next_page = request.args.get('next')
                    if not next_page or url_parse(next_page).netloc != '':
                        next_page = url_for('index')
                    return redirect(next_page)
                else:
                    flash('Invalid Password')
                    return redirect(url_for('login'))
            else:
                flash('Invalid Username')
                return redirect(url_for('login'))
            return render_template('login.html', form=form)
        else:
            req_data = request.get_json(force=True)
            accCheck = Conta.objects(userSetting__email = req_data['username'])
            if accCheck:
                if check_password_hash(accCheck[0].userSetting.password , req_data['password']):
                    expires = timedelta(minutes=2)
                    token = create_access_token(req_data['username'], expires_delta=expires)
                    refresh_token = create_refresh_token(identity = req_data['username'])
                    return make_response(jsonify({
                        'message': 'Usuario '+ req_data['username'] + ' logado.',
                        'access_token': token,
                        'refresh_token': refresh_token,
                        'username' : accCheck[0].userSetting.username ,
                        'email' : accCheck[0].userSetting.email
                    })), 200
                else:
                    return make_response(jsonify({"message":"wrong credentials"})), 204
            else:
                return make_response(jsonify({"message":"wrong credentials"})), 204


    return render_template('login.html', form=form)

@app.errorhandler(404)
def not_found(error):
    """ error handler """
    LOG.error(error)
    return make_response(jsonify({'error': 'Not found'}), 404)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():

        # -------------
        hashpass2 = generate_password_hash(form.password.data)
        newUserSetting = User_Setting(form.username.data,form.email.data,hashpass2)
        newAcc = Conta( datetime.now() , userSetting = newUserSetting ).save()
        print(newAcc)
        print(newAcc.userSetting.username)
        print(newAcc.devices)

        login_user(newAcc)
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/getDeviceSettingOLD' , methods=['GET', 'POST'])
def getDeviceSettingOLD ():
    req_data = request.get_json(force=True)
    deviceHash = req_data['deviceHash']
    if (deviceHash):
        deviceAcc = Conta.objects.filter(devices__deviceHash = deviceHash)
        if (deviceAcc):
            accFound = deviceAcc[0]
            if accFound:
                return make_response(jsonify({
                    'mensagem' : 'Chegou!! Deu certo! Device setting recebido!',
                    'deviceAlias': accFound.devices[0].deviceAlias,
                    'deviceHash': accFound.devices[0].deviceHash,
                    'blockImgPorn': accFound.devices[0].deviceSetting[0].blockImgPorn,
                    'blockImgNud' : accFound.devices[0].deviceSetting[0].blockImgNud,
                    'blockSitePorn' : accFound.devices[0].deviceSetting[0].blockSitePorn,
                    'blockSiteNud' : accFound.devices[0].deviceSetting[0].blockSiteNud,
                    'notifDesinst' : accFound.devices[0].deviceSetting[0].notifDesinst,
                    'notiDesat' : accFound.devices[0].deviceSetting[0].notiDesat,
                    'modSilencioso' : accFound.devices[0].deviceSetting[0].modSilencioso
                })), 200
        else: return make_response(jsonify({"message":"Nao encontrei nenhum registro!"})), 204

@app.route('/saveDeviceSetting', methods=['GET', 'POST'])
def saveDeviceSetting():
	req_data = request.get_json(force=True)
	deviceAlias = req_data['deviceSetting']['deviceAlias']
	deviceHash = req_data['deviceSetting']['deviceHash']
	blockImgSugest = req_data['deviceSetting']['blockImgSugest']
	blockSiteSugest = req_data['deviceSetting']['blockSiteSugest']
	blockImgPorn = req_data['deviceSetting']['blockImgPorn']
	blockImgNud = req_data['deviceSetting']['blockImgNud']
	blockSitePorn = req_data['deviceSetting']['blockSitePorn']
	blockSiteNud = req_data['deviceSetting']['blockSiteNud']
	notifDesinst = req_data['deviceSetting']['notifDesinst']
	modSilencioso = req_data['deviceSetting']['modSilencioso']
	Conta.objects.filter(devices__deviceHash = deviceHash).update(set__devices__S__deviceSetting__blockImgPorn = blockImgPorn, set__devices__S__deviceSetting__blockImgNud = blockImgNud, set__devices__S__deviceSetting__blockSitePorn = blockSitePorn, set__devices__S__deviceSetting__blockSiteNud = blockSiteNud, set__devices__S__deviceSetting__blockImgSugest = blockImgSugest, set__devices__S__deviceSetting__blockSiteSugest = blockSiteSugest, set__devices__S__deviceSetting__notifDesinst = notifDesinst, set__devices__S__deviceSetting__modSilencioso = modSilencioso, set__devices__S__deviceAlias = deviceAlias)
	return make_response(jsonify({
		'teste' : 'rildo'
	})), 200

@app.route ('/createDeviceOLD', methods=['GET', 'POST'])
def createDeviceOLD (): #RECEBE deviceHash e email
    req_data = request.get_json(force=True)
    deviceHash = req_data['deviceHash']
    username = req_data['email']
    accCheck = Conta.objects(userSetting__email = username)
    accFound = accCheck[0]
    deviceFounded =  Conta.objects.filter(id = accFound.id, devices__deviceHash = deviceHash)
    print("Vendo as variáveis achadas.. ", username , "---- " , deviceHash)
    if(accFound and not deviceFounded):
        newDeviceSetting = DeviceSettings ("false", "false", "false", "false", "false", "false", "false" )
        newDevice = Devices()
        newDevice.deviceAlias = "Pc do(a) " + accFound.userSetting[0].username
        newDevice.deviceHash = deviceHash
        newDevice.deviceSetting = [newDeviceSetting]
        print ("Criando o device novo...")
        teste = Conta.objects.filter(id = accFound.id)
        print(teste)
        print(newDevice)
        Conta.objects.filter(id = accFound.id).update(push__devices = newDevice)

        accFound.reload()
        print(accCheck)
        print(accFound)
        return make_response(jsonify({
            'deviceAlias': accFound.devices[0].deviceAlias,
            'deviceHash': accFound.devices[0].deviceHash,
            'blockImgPorn': accFound.devices[0].deviceSetting[0].blockImgPorn,
            'blockImgNud' : accFound.devices[0].deviceSetting[0].blockImgNud,
            'blockSitePorn' : accFound.devices[0].deviceSetting[0].blockSitePorn,
            'blockSiteNud' : accFound.devices[0].deviceSetting[0].blockSiteNud,
            'notifDesinst' : accFound.devices[0].deviceSetting[0].notifDesinst,
            'notiDesat' : accFound.devices[0].deviceSetting[0].notiDesat,
            'modSilencioso' : accFound.devices[0].deviceSetting[0].modSilencioso
        })), 200
    else: return make_response(jsonify({"message":"Nao encontrei nenhum registro!"})), 204


@app.route('/getAccountDevices', methods=['GET', 'POST'])
def getAccountDevices ():
    req_data = request.get_json(force=True)
    username = req_data['username']
    responseData = {}
    dataRildo = []
    if(username):
        deviceAcc = Conta.objects.filter(userSetting__email = username)
        if(deviceAcc):
            print("Rildo trampando......",deviceAcc)
            accFound = deviceAcc[0]
            if (len(accFound.devices) > 0):
                for devices in accFound.devices:
                    item = {'deviceAlias' : devices.deviceAlias}
                    dataRildo.append(item)
                    #responseData['deviceAlias'] = devices.deviceAlias
                    #json_data_response = json.dumps(responseData)
                    #responseData = {"DeviceAlias" : devices.deviceAlias}
                    print (devices.deviceAlias)
                json_data_response = json.dumps(dataRildo)
                return make_response(json_data_response), 200
            else: return make_response(jsonify({"message":"Nao encontreiii nenhum dispositivo nessa conta"})), 204

@app.route('/getDeviceSetting' , methods=['GET', 'POST'])
def getDeviceSetting ():
    req_data = request.get_json(force=True)
    deviceHash = req_data['deviceHash']
    if (deviceHash):
        deviceAcc = Conta.objects.filter(devices__deviceHash = deviceHash)
        if (deviceAcc):
            accFound = deviceAcc[0]
            if accFound:
                return make_response(jsonify({
                    'mensagem' : 'Chegou!! Deu certo! Device setting recebido!',
                    'deviceAlias': accFound.devices[0].deviceAlias,
                    'deviceHash': accFound.devices[0].deviceHash,
                    'blockImgPorn': accFound.devices[0].deviceSetting[0].blockImgPorn,
                    'blockImgNud' : accFound.devices[0].deviceSetting[0].blockImgNud,
                    'blockSitePorn' : accFound.devices[0].deviceSetting[0].blockSitePorn,
                    'blockSiteNud' : accFound.devices[0].deviceSetting[0].blockSiteNud,
                    'notifDesinst' : accFound.devices[0].deviceSetting[0].notifDesinst,
                    'notiDesat' : accFound.devices[0].deviceSetting[0].notiDesat,
                    'modSilencioso' : accFound.devices[0].deviceSetting[0].modSilencioso
                })), 200
        else: return make_response(jsonify({"message":"Nao encontrei nenhum registro!"})), 204



@app.route ('/createDevice', methods=['GET', 'POST'])
def createDevice (): #RECEBE deviceHash e email
    req_data = request.get_json(force=True)
    deviceHash = req_data['deviceHash']
    username = req_data['email']
    accCheck = Conta.objects(userSetting__email = username)
    accFound = accCheck[0]
    deviceFounded =  Conta.objects.filter(id = accFound.id, devices__deviceHash = deviceHash)
    print("Vendo as variáveis achadas.. ", username , "---- " , deviceHash)
    if(accFound and not deviceFounded):
        newDeviceSetting = DeviceSettings ("false", "false", "false", "false", "false", "false", "false" )
        newDevice = Devices()
        newDevice.deviceAlias = ""#"Pc do(a) " + accFound.userSetting[0].username
        newDevice.deviceHash = deviceHash
        newDevice.deviceSetting = [newDeviceSetting]
        #Conta.objects.filter(id = newAcc.id, devices__deviceHash = "adsdf23ej23nfj", devices__browserHistory__siteUrl = "www.google2.com.br").update(push__devices__S__browserHistory = browserHistory3) #update(set__devices__S__deviceHash="RildoFunfou", set__devices__0__browserHistory__S__siteUrl = "www.rildo.com.br")
        Conta.objects.filter(id = accFound.id).update(push__devices = newDevice)
        accFound.reload()
        deviceToReturn = findDeviceByHash(accCheck[0], deviceHash)
        return make_response(jsonify({
            'deviceAlias': deviceToReturn.deviceAlias,
            'deviceHash': deviceToReturn.deviceHash,
            'blockImgPorn': deviceToReturn.deviceSetting.blockImgPorn,
            'blockImgNud' : deviceToReturn.deviceSetting.blockImgNud,
            'blockSitePorn' : deviceToReturn.deviceSetting.blockSitePorn,
            'blockSiteNud' : deviceToReturn.deviceSetting.blockSiteNud,
            'notifDesinst' : deviceToReturn.deviceSetting.notifDesinst,
            'notiDesat' : deviceToReturn.deviceSetting.notiDesat,
            'modSilencioso' : deviceToReturn.deviceSetting.modSilencioso
        })), 200
    else: return make_response(jsonify({"message":"Nao encontrei nenhum registro!"})), 204




@app.route('/getDeviceHash', methods = ['GET', 'POST'])
def getDeviceHash():
    req_data = request.get_json(force=True)
    username = req_data['username']
    deviceAlias = req_data['deviceAlias']
    if (deviceAlias and username):
        accCheck = Conta.objects(userSetting__email = username)
        deviceFound = findDeviceByAlias(accCheck[0], deviceAlias)
        print("Vendo o device achado: ",deviceFound)
        if (deviceFound):
            return make_response(jsonify({
                'mensagem':"Segue o device hash",
                'deviceAlias': deviceFound.deviceAlias,
                'deviceHash' : deviceFound.deviceHash,
                'blockImgPorn': deviceFound.deviceSetting.blockImgPorn,
                'blockImgNud' : deviceFound.deviceSetting.blockImgNud,
		'blockImgSugest' : deviceFound.deviceSetting.blockImgSugest,
                'blockSitePorn' : deviceFound.deviceSetting.blockSitePorn,
                'blockSiteNud' : deviceFound.deviceSetting.blockSiteNud,
		'blockSiteSugest' : deviceFound.deviceSetting.blockSiteSugest,
                'notifDesinst' : deviceFound.deviceSetting.notifDesinst,
                'modSilencioso' : deviceFound.deviceSetting.modSilencioso
            })), 200
        else: return make_response(jsonify({"message":"Não encontrei nenhum device com esse alias! kkk"})), 204



@app.route('/updateClientDevice', methods = ['GET', 'POST'])
def updateClientDevice():
    req_data = request.get_json(force=True)
    username = req_data['username']
    deviceHash = req_data['deviceHash']
    if (username and deviceHash):
        accCheck = Conta.objects(userSetting__email = username)
        deviceToReturn = findDeviceByHash(accCheck[0], deviceHash)
        if (deviceToReturn):
            return make_response(jsonify({
                'mensagem' : 'Chegou!! Deu certo! Device setting recebido!',
                'deviceAlias': deviceToReturn.deviceAlias,
                'deviceHash': deviceToReturn.deviceHash,
		'blockImgSugest' : deviceToReturn.deviceSetting.blockImgSugest,
		'blockSiteSugest' : deviceToReturn.deviceSetting.blockSiteSugest,
                'blockImgPorn': deviceToReturn.deviceSetting.blockImgPorn,
                'blockImgNud' : deviceToReturn.deviceSetting.blockImgNud,
                'blockSitePorn' : deviceToReturn.deviceSetting.blockSitePorn,
                'blockSiteNud' : deviceToReturn.deviceSetting.blockSiteNud,
                'notifDesinst' : deviceToReturn.deviceSetting.notifDesinst,
                'modSilencioso' : deviceToReturn.deviceSetting.modSilencioso
            })), 200
        else: return make_response(jsonify({"message":"Não encontrei nenhum device com esse hash! kkk"})), 204

def findDeviceByHash(accFound, deviceHash):
    for devices in accFound.devices:
        if (devices.deviceHash == deviceHash):
            print (devices)
            return (devices)

def findDeviceByAlias(accFound, deviceAlias):
    print("Procurando um device na conta, por alias")
    for devices in accFound.devices:
        if (devices.deviceAlias == deviceAlias):
            print (devices)
            return (devices)
    return None





@app.route('/rekognitionOLD', methods=['GET', 'POST'])
def rekognitionOLD():
    print ("Começa o serviço rekognition")
    req_data = request.get_json(force=True)

    if (req_data['url'] and req_data['deviceHash']): #esta quebrando qdo nao encontra o campo
        print("Variáveis recebidas corretamente")
        urlReceived = req_data['url']
        client=boto3.client('rekognition','us-west-2')
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36'}
        imgUrl = requests.get(urlReceived, headers=headers)
        if (imgUrl.status_code == 200):
            print("Leu a img corretamente!!")
            existentImg = ImgCache.objects.filter( imgBase64 = imgUrl.content)
            if not (existentImg):
                newImg = ImgCache( datetime.datetime.now() , imgUrl.content ).save()
                print("Criou a imagem no cache corretamente?!")
                print(newImg)
                response = client.detect_moderation_labels(Image={'Bytes': imgUrl.content})
                if (len(response['ModerationLabels']) > 0):
                    print("A amazon ja avaliou a msg e tem coisa ai!")
                    for i in response['ModerationLabels']:
                        newModerationLabels = ModerationLabels (i["Confidence"], i["Name"], i["ParentName"])
                        ImgCache.objects.filter(id = newImg.id).update(push__moderationLabels = newModerationLabels)
                else:
                    print("A amazon avaliou mas nao achou nada!!")
                newImg.reload()
            else: print ("Imagem ja existia!!")
            imgToRespond = ImgCache.objects.filter( imgBase64 = imgUrl.content)
            print("Pegando a img que será retornada!!")
            return make_response(jsonify({
                'moderationLabels': imgToRespond[0].moderationLabels
            })), 200
        else:
            print ("Não consegui ler a imagem recebida através da URL")
            return make_response(jsonify({"message":"wrong information sadaspoha! kkk"})), 204





@app.route('/rekognition', methods=['GET', 'POST'])
def rekognition():
	rildoBoto = botocore.session.get_session()
#	print(rildoBoto.get_credentials().access_key)
	boto3Session = boto3.Session(aws_access_key_id= rildoBoto.get_credentials().access_key, aws_secret_access_key = rildoBoto.get_credentials().secret_key)
	print ("Comeca o servico rekognition")
#	print("Rildo tentando ver se a variavel boto3 ta rodando:::: ", BOTO3_ACCESS_KEY)
	req_data = request.get_json(force=True)

	if (req_data['url']):
		print("Variaveis recebidas corretamente")
		urlReceived = req_data['url']
		client = boto3Session.client('rekognition',rildoBoto.get_config_variable('region'))
		headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36'}
		print("Vendo antes de criar a variavel headers>>>> ", urlReceived)
		session = requests.Session()
		session.trust_env = False
		now = datetime.now()
		imgUrl = session.get(urlReceived, headers=headers)
		now2 = datetime.now()
		print("Essa request levou::: " , (now2 - now).total_seconds())
		print("Vendo depois de fzr a request para ler a img")
		if (imgUrl.status_code == 200):
			print("Leu a img corretamente!!")
			existentImg = ImgCache.objects.filter( imgBase64 = imgUrl.content)
			if not (existentImg):
                		newImg = ImgCache( datetime.now() , imgUrl.content, urlReceived ).save()
                		print("Criou a imagem no cache corretamente?!")
                		print(newImg)
                		response = client.detect_moderation_labels(Image={'Bytes': imgUrl.content}, MinConfidence=60)
                		if (len(response['ModerationLabels']) > 0):
                    			print("A amazon ja avaliou a msg e tem coisa ai!")
                    			for i in response['ModerationLabels']:
                        			newModerationLabels = ModerationLabels (i["Confidence"], i["Name"], i["ParentName"])
                        			ImgCache.objects.filter(id = newImg.id).update(push__moderationLabels = newModerationLabels)
                		else:
                    			print("A amazon avaliou mas nao achou nada!!")
                		newImg.reload()
			else: print ("Imagem ja existia!!")
			imgToRespond = ImgCache.objects.filter( imgBase64 = imgUrl.content)
			print("Pegando a img que sera retornada!!")
			return make_response(jsonify({
				'moderationLabels': imgToRespond[0].moderationLabels})), 200
		else:
			print ("Nao consegui ler a imagem recebida atraves da URL >>>>>>>>>>> ", urlReceived)
			return make_response(jsonify({"message":"wrong information sadaspoha! kkk"})), 204

@app.route('/checkDeviceName', methods=['GET', 'POST'])
def checkDeviceName():
	req_data = request.get_json(force=True)
	deviceHash = req_data['deviceHash']
	username = req_data['username']
	deviceAlias = req_data['deviceAlias']
	if (username and deviceAlias and deviceHash):
		accCheck = Conta.objects.filter(userSetting__email = username)
		deviceFound = findDeviceByAlias(accCheck[0], deviceAlias)
		if(deviceFound and deviceFound.deviceHash != deviceHash):
			return make_response(jsonify({"message":"Este nome de dispositivo ja existe na conta"})), 204
		else: return make_response(jsonify({"message":"Nome livre para ser usado nesta conta"})), 200
