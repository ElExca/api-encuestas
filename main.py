# run.py

from flask import Flask, jsonify, request, make_response
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from bson import ObjectId

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/mantenimiento'
app.config['JWT_SECRET_KEY'] = '0cc175b9c0f1b6a831c399e269772661'
mongo = PyMongo(app)
jwt = JWTManager(app)

def obtener_puntos(respuestas, preguntas):
    total_puntos = 0
    for respuesta in respuestas:
        pregunta_texto = respuesta.get('pregunta')
        respuesta_texto = respuesta.get('respuesta')

        # Buscar la pregunta en la lista de preguntas
        pregunta = next((pregunta for pregunta in preguntas if pregunta['texto'] == pregunta_texto), None)

        if pregunta and pregunta['tipo'] == 'opcion_multiple':
            # Verificar si la respuesta está en las opciones predefinidas
            opcion = next((opcion for opcion in pregunta['respuestas'] if opcion['opcion'] == respuesta_texto), None)
            if opcion:
                total_puntos += opcion.get('puntos', 0)
        # Puedes agregar más lógica para manejar otros tipos de preguntas aquí

    return total_puntos

def verificar_premio(respuestas, preguntas):
    puntos_obtenidos = obtener_puntos(respuestas, preguntas)
    return puntos_obtenidos > 3


# Registro de usuario
@app.route('/api/registro', methods=['POST'])
def registro():
    datos_usuario = request.get_json()
    if 'username' not in datos_usuario or 'password' not in datos_usuario:
        return jsonify({'mensaje': 'Se requiere nombre de usuario y contraseña'}), 400

    usuario_existente = mongo.db.usuarios.find_one({'username': datos_usuario['username']})
    if usuario_existente:
        return jsonify({'mensaje': 'El nombre de usuario ya está en uso'}), 409

    datos_usuario['password'] = generate_password_hash(datos_usuario['password'])
    mongo.db.usuarios.insert_one(datos_usuario)
    return jsonify({'mensaje': 'Registro exitoso'})

# Inicio de sesión
@app.route('/api/login', methods=['POST'])
def login():
    datos_login = request.get_json()
    if 'username' not in datos_login or 'password' not in datos_login:
        return jsonify({'mensaje': 'Se requiere nombre de usuario y contraseña'}), 400

    usuario = mongo.db.usuarios.find_one({'username': datos_login['username']})
    if usuario and check_password_hash(usuario['password'], datos_login['password']):
        # Generar token de sesión (puedes utilizar JWT u otro método)
        token_sesion = create_access_token(identity=str(usuario['_id']))

        respuesta = make_response(jsonify({'mensaje': 'Inicio de sesión exitoso'}), 200)
        respuesta.headers['Authorization'] = 'Bearer ' + token_sesion
        return respuesta
    else:
        return jsonify({'mensaje': 'Credenciales inválidas'}), 401

# Ruta protegida que requiere token JWT
@app.route('/api/ruta_protegida', methods=['GET'])
@jwt_required()
def ruta_protegida():
    usuario_actual = get_jwt_identity()
    return jsonify(logged_in_as=usuario_actual), 200

@app.route('/api/encuestas', methods=['POST'])
def crear_encuesta():
    nueva_encuesta = request.get_json()
    encuestas = mongo.db.encuestas
    encuesta_id = encuestas.insert_one(nueva_encuesta).inserted_id
    return jsonify({'mensaje': 'Encuesta creada exitosamente', 'id_encuesta': str(encuesta_id)})

@app.route('/api/encuestas', methods=['GET'])
def obtener_encuestas():
    encuestas = mongo.db.encuestas.find()
    return jsonify({'encuestas': list(encuestas)})

@app.route('/api/encuestas/<string:encuesta_id>', methods=['GET'])
def obtener_encuesta(encuesta_id):
    encuesta = mongo.db.encuestas.find_one({'_id': ObjectId(encuesta_id)})
    if encuesta:
        # Convertir ObjectId a str antes de devolver la respuesta JSON
        encuesta['_id'] = str(encuesta['_id'])
        return jsonify({'encuesta': encuesta})
    else:
        return jsonify({'mensaje': 'Encuesta no encontrada'}), 404


def obtener_preguntas_de_la_encuesta(encuesta_id):
    # Recupera las preguntas de la encuesta desde la base de datos
    encuesta = mongo.db.encuestas.find_one({'_id': ObjectId(encuesta_id)})

    if encuesta:
        return encuesta.get('preguntas', [])
    else:
        return []


@app.route('/api/encuestas/<string:encuesta_id>/responder', methods=['POST'])
def responder_encuesta(encuesta_id):
    data = request.get_json()

    if 'respuestas' in data:
        preguntas = obtener_preguntas_de_la_encuesta(
            encuesta_id)  # Implementa la lógica para obtener las preguntas de la base de datos
        preguntas_respuestas = data['respuestas']

        for respuesta in preguntas_respuestas:
            respuesta['puntos'] = obtener_puntos([respuesta], preguntas)

        if verificar_premio(preguntas_respuestas, preguntas):
            return jsonify({'mensaje': 'Respuesta registrada exitosamente. ¡Felicidades! Has ganado un premio'})
        else:
            return jsonify({'mensaje': 'Respuesta registrada exitosamente'})
    else:
        return jsonify({'mensaje': 'Formato de respuesta no válido'}), 400


if __name__ == '__main__':
    app.run(debug=True)
