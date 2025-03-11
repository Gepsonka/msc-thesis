import sqlite3
from flask import Flask, request, jsonify

from lib.crypt import generate_keys
from server.lib.error import FIELD_MISSING_CODE, NO_DATA_CODE

db = sqlite3.connect("./data.db")

cursor = db.cursor()

print("Wiping out stored client hashes...")
cursor.execute('DELETE FROM hash')
db.commit()

cursor.execute("SELECT * FROM server_keys")

server_keys = cursor.fetchall()

if len(server_keys) == 0:
  print("Server keys not found... creating")
  private_key, public_key = generate_keys()
  cursor.execute("INSERT INTO server_keys (private_key, public_key) VALUES (?, ?)", (private_key.to_string().hex(), public_key.to_string().hex()))
  db.commit()
  print("Server keys created")

cursor.close()

app = Flask(__name__)

@app.route('/api/keys', methods=['GET'])
def keys():
  cursor = db.cursor()

  data = request.get_json()

  if data is None:
     return jsonify({"message": "No data received", "code": NO_DATA_CODE}), 400
  
  if data.get("public_key") is None or data.get("common_public_key") is None or data.get("chameleon_hash") is None:
     return jsonify({"message": "Field is missing", "code": FIELD_MISSING_CODE}), 400
  
  cursor.execute("INSERT INFO hash (client_public_key, common_public_key, chameleon_hash) VALUES (?, ?, ?)", (data.get("public_key"), data.get("common_public_key"), data.get("chameleon_hash")))
  db.commit()

  cursor.close()

  return jsonify({"code": "OK"}), 200


@app.route('/api/message')
def message():
   cursor = db.cursor()

   cursor.close()

if __name__ == '__main__':
    app.run(debug=True)
    db.close()