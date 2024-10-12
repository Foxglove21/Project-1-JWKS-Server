# tests/test_server.py
import pytest
import requests
import multiprocessing
import time
import datetime
import jwt
from http.server import HTTPServer
from main import MyServer, HOSTNAME, SERVERPORT, int_to_base64  # Import your server code here

BASE_URL = "http://localhost:8080"

# Utility function to start the server in a separate process
def start_server():
    server = HTTPServer((HOSTNAME, SERVERPORT), MyServer)
    server.serve_forever()

@pytest.fixture(scope='module', autouse=True)
def server():
    # Start the server in a separate process
    server_process = multiprocessing.Process(target=start_server)
    server_process.start()
    time.sleep(1)  # Give the server a moment to start
    yield
    server_process.terminate()  # Stop the server when tests are done

def test_int_to_base64():
    """Test the int_to_base64 utility function."""
    assert int_to_base64(12345) == 'MDk'  # Add relevant test cases

def test_get_jwks():
    """Test the GET /.well-known/jwks.json endpoint."""
    response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
    assert response.status_code == 200
    json_data = response.json()
    assert 'keys' in json_data
    assert len(json_data['keys']) == 1
    key = json_data['keys'][0]
    assert key['alg'] == 'RS256'
    assert key['kid'] == 'goodKID'

def test_post_auth_token():
    """Test the POST /auth endpoint."""
    response = requests.post(f"{BASE_URL}/auth")
    assert response.status_code == 200
    token = response.text
    assert token is not None
    # Decode the JWT token and check the payload
    import jwt
    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload['user'] == 'username'

def test_post_auth_expired_token():
    """Test the POST /auth endpoint with expired parameter."""
    response = requests.post(f"{BASE_URL}/auth?expired=true")
    assert response.status_code == 200
    token = response.text
    assert token is not None
    # Decode the JWT token and check if it's expired
    import jwt
    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload['user'] == 'username'
    assert payload['exp'] < time.time()  # Ensure the token is expired

def test_unsupported_methods():
    """Test unsupported HTTP methods return 405."""
    for method in ['put', 'patch', 'delete', 'head']:
        response = requests.request(method, f"{BASE_URL}/auth")
        assert response.status_code == 405

def test_invalid_path():
    """Test that invalid paths return 405."""
    response = requests.get(f"{BASE_URL}/invalidpath")
    assert response.status_code == 405

#attempt to make test suite 
#Used chatgpt using the prompt "write a test suite for this from [inserted code]" so basically all of this is chatgpt
#Does not currently work
#Trying to figure out where chatgpt has lead me astray
#pretty sure I imported something wrong
