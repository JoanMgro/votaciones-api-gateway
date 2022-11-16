from src_gateway import create_app
from flask_cors import CORS

from flask_jwt_extended import JWTManager


import json

from waitress import serve
from flask import request
from flask import jsonify



from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required

import  datetime
import requests
import re





# Flask instance app
#app = Flask(__name__)
app = create_app()

#registrando el app en cors
cors = CORS(app)



jwt = JWTManager(app)




@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url=server_config["url-backend-seguridad"]+'/usuarios/validar'

    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60*24)
        access_token = create_access_token(identity=user, expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"msg": "Bad username or password"}), 401
#################################################
@app.before_request
def before_request_callback():
    endPoint=limpiarURL(request.path)
    excludedRoutes=["/login"]
    if excludedRoutes.__contains__(request.path):
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        if usuario["rol"]is not None:
            tienePersmiso=validarPermiso(endPoint,request.method,usuario["rol"]["_id"])
            if not tienePersmiso:
                return jsonify({"message": "Permission denied"}), 401
        else:
            return jsonify({"message": "Permission denied"}), 401
def limpiarURL(url):
    partes = url.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
    return url
def validarPermiso(endPoint,metodo,idRol):
    url=server_config["url-backend-seguridad"]+"/permisos-roles/validar-permiso/rol/"+str(idRol)
    tienePermiso=False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body={
        "url":endPoint,
        "metodo":metodo
    }
    response = requests.get(url,json=body, headers=headers)
    try:
        data=response.json()
        if("_id" in data):
            tienePermiso=True
    except:
        pass
    return tienePermiso



################################################
#Endpoint administrador - Candidatos

@app.route("/candidatos",methods=['GET'])
def getCandidatos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/candidatos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/crear",methods=['POST'])
def crearCandidato():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/candidatos/crear'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)
@app.route("/candidatos/ver/<string:id>",methods=['GET'])
def getCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/candidatos/ver/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/candidatos/modificar/<string:id>",methods=['PUT'])
def modificarCandidato(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/candidatos/modificar/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/candidatos/eliminar/<string:id>",methods=['DELETE'])
def eliminarCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/candidatos/eliminar/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route('/candidatos/<id_candidato>/partidos/<id_partido>', methods=['PUT'])
def asignarPartidoACandidato(id_candidato, id_partido):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/candidatos/' + id_candidato + '/partidos/' + id_partido
    response = requests.put(url, headers=headers)
    json = response.json()
    return jsonify(json)
###########################################################
#Endpoint administrador - Mesas

@app.route("/mesas",methods=['GET'])
def getMesas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/mesas'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/mesas/crear",methods=['POST'])
def crearMesa():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/mesas/crear'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)
@app.route("/mesas/ver/<string:id>",methods=['GET'])
def getMesa(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/mesas/ver/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/mesas/modificar/<string:id>",methods=['PUT'])
def modificarMesa(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/mesas/modificar/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/mesas/eliminar/<string:id>",methods=['DELETE'])
def eliminarMesa(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/mesas/eliminar/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

###########################################################
#Endpoint administrador - Partidos

@app.route("/partidos",methods=['GET'])
def getpartidos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/partidos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/partidos/crear",methods=['POST'])
def crearPartido():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/partidos/crear'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)
@app.route("/partidos/ver/<string:id>",methods=['GET'])
def getPartido(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/partidos/ver/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/partidos/modificar/<string:id>",methods=['PUT'])
def modificarPartido(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/partidos/modificar/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/partidos/eliminar/<string:id>",methods=['DELETE'])
def eliminarPartido(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/partidos/eliminar/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

###########################################################
#Endpoint administrador - Resultados

@app.route("/resultados",methods=['GET'])
def getResultados():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/resultados'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultados/crear/<id_candidato>/mesa/<id_mesa>",methods=['POST'])
def crearResultado(id_candidato, id_mesa):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/resultados/crear/' + id_candidato + '/mesa/' + id_mesa
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)
@app.route("/resultados/ver/<string:id>",methods=['GET'])
def getResultado(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/resultados/ver/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route('/resultados/modificar/<id>/candidato/<id_candidato>/mesa/<id_mesa>', methods =['PUT'])
def modificarResultado(id, id_candidato, id_mesa):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/resultados/modificar/'+id + '/candidato/' + id_candidato + '/mesa/' + id_mesa
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/resultados/eliminar/<string:id>",methods=['DELETE'])
def eliminarResultado(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/resultados/eliminar/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

###########################################################
#Endpoint administrador - Operaciones resultados

@app.route("/resultados/votos-total-candidatos",methods=['GET'])
def getVotosTotales():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/resultados/votos-total-candidatos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)



@app.route("/resultados/participacion-mesa",methods=['GET'])
def getParticipacionMesa():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = server_config["url-backend-transaccional"] + '/resultados/participacion-mesa'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
################################################
## Test service

@app.route('/test', methods =['GET'])
def test():
    json={}
    json['message'] = "Server running"
    return jsonify(json)

#################################################
def load_server_config():
    #baser_dir = os.getcwd() + '/Votaciones/config.json'
    with open('config.json', 'r') as json_file :
        # json.load -> file obj and returns a json obj
        data = json.load(json_file)
        return data

server_config = load_server_config()

if __name__ == '__main__':

    print(f"* SERVING ON http://{server_config['url-backend']}:{server_config['port']} ")
    serve(app, host=server_config['url-backend'], port=server_config['port'])

