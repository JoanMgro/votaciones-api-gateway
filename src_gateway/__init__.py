
from flask import Flask

#imports de las vars bp_xxx de paquete Routes



#codigo del mongo
# client = pymongo.MongoClient("mongodb+srv://grupociclo4:<password>@clusterciclo4a.lwuilv8.mongodb.net/?retryWrites=true&w=majority")
# db = client.test


#imports de las vars bp_xxx de paquete Routes
# from Votaciones.Routes.routescandidato import bp_candidatos
# from Votaciones.Routes.routesmesa import bp_mesas
# from Votaciones.Routes.routespartidos import bp_partido
# from Votaciones.Routes.routesresultado import bp_resultados


def create_app():
    # create and configure the app
    app = Flask(__name__, instance_relative_config=False)



    #registrando los blueprints de las rutas

    app.config["JWT_SECRET_KEY"] = "super-secret"  # Cambiar por el que se conveniente



    return app