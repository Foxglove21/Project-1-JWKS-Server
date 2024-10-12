#Claire Pacquing
#cfp0029
#Used Professor Jacob Hochstetler skeleton

from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
import json
import jwt
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs

#Please note I did my best to lint
#used VS code Pylint
#didn't know what a docstring meant so I used chatgpt
#used prompt "What is a docstring in python"

#sets host and server port
HOSTNAME = "localhost"
SERVERPORT = 8080

#generates RSA encryption/decryption keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

#pem encryption being set
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    """creating a JWKS server via class"""

    #used chatgpt to find out what send_response means
    #used prompt "send_response meaning in python"
    def do_put(self):
        """Sends a HTTP code 405 to client"""
        self.send_response(405)
        self.end_headers()
        return

    def do_patch(self):
        """Sends a HTTP code 405 to client"""
        self.send_response(405)
        self.end_headers()
        return

    def do_delete(self):
        """Sends a HTTP code 405 to client"""
        self.send_response(405)
        self.end_headers()
        return

    def do_head(self):
        """Sends a HTTP code 405 to client"""
        self.send_response(405)
        self.end_headers()
        return

    def do_post(self):
        """Posts a path for the user"""
        #sets path
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            #sets token for user and its expiration date
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            #checks if pamas aka parsed_path query is expired
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            #writes encoded jwt using utf-8 to a file
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_get(self):
        """gets response from client using json and keys"""
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            #sets keys information
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    #creates webserver
    webServer = HTTPServer((HOSTNAME, SERVERPORT), MyServer)
    try:
        #webserver now has an infinite loop and can handle requests
        #used chatgpt to find out what serve_forever() means
        #used prompt "what does serve_forever() mean
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
