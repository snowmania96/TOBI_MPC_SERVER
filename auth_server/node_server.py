import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta
import time

import jwt
from flask import Flask, jsonify,  request
from flask_cors import CORS
from webauthn import verify_authentication_response, verify_registration_response
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes
from webauthn.helpers.structs import AuthenticationCredential, RegistrationCredential
import redis
import mysql.connector
import firebase_admin
from firebase_admin import auth

from logging import getLogger, basicConfig, DEBUG, INFO

debug = os.getenv("AUTH_NODE_DEBUG", "false").lower() == "true"

logger = getLogger(__name__)
if debug:
    basicConfig(level=DEBUG)
else:
    basicConfig(level=INFO)

redis_host = os.getenv("REDIS_HOST", "redis")
redis_port = os.getenv("REDIS_PORT", 6379)
redis_password = os.getenv("REDIS_PASSWORD", "")

logger.info(f"Connecting to redis cache: {redis_host}:{redis_port}")
cache = redis.Redis(
    host=os.getenv("REDIS_HOST", "redis"),
    port=os.getenv("REDIS_PORT", 6379),
    password=os.getenv("REDIS_PASSWORD", ""),
    decode_responses=True,
)

# This is my server ID
server_id = os.getenv("SERVER_IDENTIFIER", os.urandom(32).hex())

app = Flask(__name__)
cors = CORS(app)
app.config["CORS_HEADERS"] = ["Content-Type", "Authorization"]
app.config["SECRET_KEY"] = os.getenv("AUTH_NODE_SECRET", "DEVELOPMENT MODE")

# Store the challenges that Ive issued. Dict of dicts, keyed by challenge.
CHALLENGE_TIMEOUT = 60  # seconds


# Firebase setup
use_firebase = True
firebase_cert = os.environ.get("FIREBASE_CERTIFICATE", None)
if firebase_cert is not None and os.path.exists(firebase_cert):
    cred = firebase_admin.credentials.Certificate(firebase_cert)
    firebase_app = firebase_admin.initialize_app(cred)
else:
    logger.error(
        "No service account key detected for Firebase. Disabling this form of login."
    )
    use_firebase = False


def get_db_connection():
    return mysql.connector.connect(
        host=os.environ.get("MYSQL_HOST", "localhost"),
        port=int(os.environ.get("MYSQL_PORT", 3306)),
        database=os.environ.get("MYSQL_DATABASE", "mydatabase"),
        user=os.environ.get("MYSQL_USER", "root"),
        password=os.environ.get("MYSQL_PASSWORD", ""),
    )


# Attempt to connect to the database. If it fails, retry every 5 seconds until the wait budget is exhausted.
# This is to allow the database to start up before the auth server.
t0 = time.time()
wait_budget = 300  # seconds
while (time.time() - t0) < wait_budget:
    try:
        get_db_connection()
        logger.info("Connected to MySQL database successfully.")
        break
    except Exception as e:
        logger.error(e)
        logger.info("Failed to connect to MySQL database. Retrying...")
        time.sleep(5)
else:
    logger.error("Failed to connect to MySQL database. Exiting...")
    exit(1)


def get_from_cache(prefix: str, key: str, use_server_id=True):
    """Return the value associated with the key, or None if it doesn't exist"""
    if use_server_id:
        db_key = f"{server_id}:{prefix}:{key}"
    else:
        db_key = f"{prefix}:{key}"

    return cache.get(db_key)


def pop_from_cache(prefix: str, key: str, use_server_id=True):
    """Pop a value from the cache. Returns None if no such key exists"""
    if use_server_id:
        db_key = f"{server_id}:{prefix}:{key}"
    else:
        db_key = f"{prefix}:{key}"

    value = cache.get(db_key)
    if value is not None:
        cache.delete(db_key)  # Delete the key from cache if it exists
    return value


def set_to_cache(prefix: str, key: str, data, timeout=None, use_server_id=True):
    if use_server_id:
        db_key = f"{server_id}:{prefix}:{key}"
    else:
        db_key = f"{prefix}:{key}"

    cache.set(db_key, data, ex=timeout)


def add_to_cache_set(prefix: str, key: str, data, use_server_id=True):
    if use_server_id:
        db_key = f"{server_id}:{prefix}:{key}"
    else:
        db_key = f"{prefix}:{key}"

    cache.sadd(db_key, data)


def get_cache_set(prefix: str, key: str, use_server_id=True):
    """
    Retrieve the set of values stored under a key in the cache.
    Returns an empty set if the key does not exist.
    """
    if use_server_id:
        db_key = f"{server_id}:{prefix}:{key}"
    else:
        db_key = f"{prefix}:{key}"

    # If this doesn't exist, return an empty set
    if cache.exists(db_key) == 0:
        return set()

    return cache.smembers(db_key)


def delete_from_cache(prefix: str, key: str, use_server_id=True):
    if use_server_id:
        db_key = f"{server_id}:{prefix}:{key}"
    else:
        db_key = f"{prefix}:{key}"

    cache.delete(db_key)


def validate_setup(data: dict) -> bool:
    return True


@app.route("/issue_passkeys_challenge", methods=["GET"])
def issue_passkeys_challenge():
    """
    Handles the GET request to issue a challenge for Passkeys authentication.

    This endpoint is used for generating a Passkeys challenge as part of the authentication process. It creates a random 32-byte nonce,
    converts it to a base64 URL-safe string, and then issues this string as a challenge. The challenge is stored in a cache with a specified
    timeout. This is typically used by clients to respond to as part of the Passkeys authentication mechanism.

    Returns:
        - JSON response containing the issued challenge.
        - HTTP status code 200 upon successful generation of the challenge.

    Response fields:
        - challenge (str): A base64 URL-safe string representing the challenge to be used for Passkeys authentication.

    Example response:
        {
            "challenge": "base64_url_safe_challenge_string"
        }
    """
    # Get a random 32 byte nonce
    nonce = secrets.token_bytes(32)
    challenge = bytes_to_base64url(nonce)

    # Keep a list of registration challenges that I've issued
    set_to_cache("registration_challenges", challenge, "", timeout=CHALLENGE_TIMEOUT)

    return jsonify({"challenge": challenge}), 200


@app.route("/verify_passkeys_registration", methods=["POST"])
def verify_passkeys_registration():
    """
    Handles the POST request to verify a Passkeys registration.

    This endpoint processes a registration request using Passkeys. It extracts user credentials and other relevant information from the request body.
    The function checks if the user ID already exists and extracts the challenge list from the setup string.
    Then, it verifies the provided challenge against known challenges. If the challenge is valid,
    it proceeds to verify the registration response. Upon successful verification, the user's credentials are stored, and a JWT token is generated
    and returned in the response.

    The setup string is a JSON object, stringified, as we will use it to generate the challenge hash. It contains the following fields:
        {
            // Payload session description to authorise alongside the registration
            "sl-mpc-setup": {
                "keygen": {
                    "n":3,
                    "t":2
                }
            },
            // The returned JWT will live this long, in seconds
            "timeout":10,
            // The challenges from the nodes that the user is using to register
            "challenges": [
                "Buuc-sjddBKjZ7_FgJIjdk9X6FPFabUtrq4H8JOUJjs",
                "sNaGW6eunpnKHksxI5uMa599GZVrgqyDtVYxgNdIZlM",
                "1H-nacj79xTtYYAFoyoTS9JD9BpfPj2mGFtwKHVsONs"
            ],
            "time":"2023-12-07T14:18:54.364Z"
        }

    Returns:
        - JSON response containing the registration status, a message, credential ID, user ID, credential details, token, and challenge hash.
        - HTTP status code 200 for a successful registration or 400 if an error occurs during registration or verification.

    Request parameters (in request body as JSON):
        - raw_credential (str): The raw credential information provided by the client's passkeys library.
        - setup_string (str): The setup string containing challenge information from all nodes.
        - origin (str): The origin information of the registration request.
        - rp_id (str): The relying party identifier.
        - user (dict): User description including the name.

    Example response:
        {
            "status": "OK",
            "message": "Registration successful.",
            "credential_id": "credential_id_string",
            "user_id": "user_name",
            "credential": "credential_info",
            "token": "jwt_token",
            "challenge_hex": "challenge_hash"
        }
    """
    # Parsing JSON payload
    data = request.get_json()

    logger.info("Received registration request")

    raw_credential = data.get("raw_credential")
    setup_string: str = data.get("setup_string")
    origin: str = data.get("origin")
    rp_id: str = data.get("rp_id")
    user_description: dict = data.get("user")

    # Check if user ID exists in MySQL
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    user_id = user_description["name"]
    cursor.execute("SELECT * FROM Accounts WHERE userid = %s", (user_id,))
    user_record = cursor.fetchone()

    if user_record:
        cursor.close()
        conn.close()
        logger.info(f"User ID {user_id} already exists")
        return jsonify({"error": "User already exists"}), 400

    setup = json.loads(setup_string)
    challenges = setup["challenges"]
    timeout = setup.get("timeout", 30)

    # Check that I recognise exactly one of the elements in the list of challenges
    for challenge in challenges:
        if get_from_cache("registration_challenges", challenge) is not None:
            logger.info(f"I recognised my own challenge: {challenge}")
            delete_from_cache("registration_challenges", challenge)
            break
    else:
        logger.info(f"No challenge recognised in challenges: {challenges}")
        return jsonify({"error": "Invalid challenge: Not recognized"}), 400

    # The challenge is the SHA256 hash of the setup string, which includes the challenge I supplied.
    challenge_hash = hashlib.sha256(setup_string.encode()).digest()

    try:
        # Verify Registration Response
        logger.info(f"Computing registration response")
        reg_credential = RegistrationCredential.parse_raw(raw_credential)
        registration_verification = verify_registration_response(
            credential=reg_credential,
            expected_challenge=challenge_hash,
            expected_origin=origin,
            expected_rp_id=rp_id,
            require_user_verification=True,
        )
        auth_credential = registration_verification.json()
        logger.info("\nRegistration Verification Successful")
        logger.info(auth_credential)
        logger.info("\n")

        # Insert credential info into user_credentials
        credential_id = reg_credential.id

        account_type = "passkeys"
        cursor.execute(
            "INSERT INTO Accounts (userid, account_type) VALUES (%s, %s)",
            (user_id, account_type),
        )

        cursor.execute(
            "INSERT INTO Passkeys (userid, credential_id, credential) VALUES (%s, %s, %s)",
            (user_id, credential_id, auth_credential),
        )

        conn.commit()
        cursor.close()
        conn.close()
        logger.debug(f"Set credential to database: {reg_credential.id}")

        token = jwt.encode(
            {
                "user_id": user_id,
                "setup_string": setup_string,
                "exp": datetime.utcnow() + timedelta(seconds=timeout),
            },
            app.config["SECRET_KEY"],
            algorithm="HS256",
        )
        logger.info(f"Generated token: {token}")

        # Return credential ID
        return (
            jsonify(
                {
                    "status": "OK",
                    "message": "Registration successful.",
                    "credential_id": bytes_to_base64url(
                        registration_verification.credential_id
                    ),
                    "user_id": user_description["name"],
                    "credential": auth_credential,
                    "token": token,
                    "challenge_hex": challenge_hash.hex(),
                }
            ),
            200,
        )
    except Exception as e:
        conn.rollback()
        cursor.close()
        conn.close()
        logger.info("Registration verification failed")
        logger.info(e)
        return jsonify({"error": f"Registration verification failed: {e}"}), 400


@app.route("/issue_authentication_challenge", methods=["GET"])
def issue_authentication_challenge():
    user_id = request.args.get("user-id")
    if user_id is None:
        return jsonify({"error": "No credential ID provided"}), 400

    # Check account type in MySQL
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT account_type FROM Accounts WHERE userid = %s", (user_id,))
    user_record = cursor.fetchone()

    if user_record is None or user_record["account_type"] != "passkeys":
        cursor.close()
        conn.close()
        logger.info(f"User ID {user_id} not associated with a passkeys account")
        return jsonify({"error": "User ID not associated with a passkeys account"}), 400

    logger.info(
        "Received authentication challenge request for user ID: {}".format(user_id)
    )

    nonce = secrets.token_bytes(32)
    challenge = bytes_to_base64url(nonce)

    # Fetch all credential IDs associated with this user ID from MySQL
    cursor.execute("SELECT credential_id FROM Passkeys WHERE userid = %s", (user_id,))
    row = cursor.fetchall()
    cursor.close()
    conn.close()
    credential_ids = [r["credential_id"] for r in row]
    logger.info(f"Got credential IDs: {credential_ids}")

    # Keep the authentication challenge in the cache, temporarily
    set_to_cache("authentication_challenges", challenge, user_id, timeout=60)

    return (
        jsonify(
            {
                "credential_ids": credential_ids,
                "challenge": challenge,
                "server_id": server_id,
            }
        ),
        200,
    )


@app.route("/verify_authentication", methods=["POST"])
def verify_authentication():
    data = request.json
    logger.info("Received authentication request")

    # First, check that I recognise one of the nonces that have been supplied. If I don't, then return an error.
    # Do this first to stop people from spamming the server with authentication requests and fishing for credentials.
    setup_json = data.get("setup")
    setup_string = data.get("setup_string")

    # The expected rp_id is the domain of the frontend page! Not the auth server address!!
    rp_id = data.get("rp_id")
    origin = data.get("origin")

    logger.info("Authenticating with setup:")
    logger.info(setup_json)

    if not validate_setup(setup_json):
        return jsonify({"error": "Invalid setup"}), 400

    # Check that the setup contains my challenge
    nonces = setup_json.get("nonces", None)
    if nonces is None:
        return jsonify({"error": "Invalid setup: No nonces"}), 400

    # Checks that the nonce I recognise is specifically keyed to my server
    if server_id not in nonces.keys():
        logger.info(f"No nonce defined for this server (I am {server_id})")
        return (
            jsonify(
                {
                    "error": f"Invalid setup: No nonce defined for this server ({server_id}). I have nonces for {nonces.keys()}"
                }
            ),
            400,
        )

    # If the nonce exists, this removes it from the cache.
    # Prevents re-use by bad actors who may have eavesdropped on the nonce.
    stored_nonce = pop_from_cache("authentication_challenges", nonces[server_id])
    if stored_nonce is None:
        logger.info("Nonce not recognized")
        return jsonify({"error": "Invalid setup: Nonce not recognized"}), 400

    # If we get here, then the nonce was recognised.
    # Now, we need to check that the credential ID is valid for this user.
    logger.info("Nonce recognized. Authenticating...")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch user credentials from MySQL
    credential_id = data.get("credential_id")
    cursor.execute(
        "SELECT credential, userid FROM Passkeys WHERE credential_id = %s",
        (credential_id,),
    )
    row = cursor.fetchone()

    cursor.close()
    conn.close()

    if row is None:
        logger.info("Credential ID not recognized for this user")
        return jsonify({"error": "Credential ID not recognized"}), 400

    user_id = row["userid"]
    
    credential = row["credential"]
    known_credential = json.loads(credential)
    logger.info(f"Got the credential JSON ({type(known_credential)}): {known_credential}")

    # Get the assertion from the user
    assertion = data.get("assertion")
    authentication_credential = AuthenticationCredential.parse_raw(assertion)

    # Use the public key I stored when the user registered
    public_key = base64url_to_bytes(known_credential["credential_public_key"])

    # The challenge is the SHA256 hash of the setup string
    challenge = hashlib.sha256(setup_string.encode()).digest()

    sign_count = data.get("sign_count")
    logger.info("SIGN COUNT: {}".format(sign_count))

    try:
        # Verify the authentication response
        verification = verify_authentication_response(
            credential=authentication_credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=public_key,
            credential_current_sign_count=sign_count,
            require_user_verification=False,
        )

        logger.info("Authentication verification:")
        logger.info(verification)
        logger.info("\n")
    except Exception as e:
        logger.info("Authentication verification failed")
        logger.info(e)
        return jsonify({"error": "Authentication verification failed"}), 400

    # Issue a JWT to the user
    timeout = setup_json.get("timeout", 30)

    token = jwt.encode(
        {
            "user_id": user_id,
            "setup_string": setup_string,
            "exp": datetime.utcnow() + timedelta(seconds=timeout),
        },
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )

    # If verification succeeded
    return (
        jsonify(
            {
                "status": "OK",
                "message": "User is authenticated.",
                "verification": verification.json(),
                "token": token,
            }
        ),
        200,
    )


@app.route("/register_google_jwt", methods=["POST"])
def register_google_jwt():
    """
    Handles the POST request to register a user with a Google JSON Web Token.

    This endpoint is used to register a new user account using a Google JWT. It first checks if OAuth2 is enabled on the server.
    If not, it returns an error. The function expects a token, payload, and UUID in the request body. It verifies the token with
    Firebase, registers the user in the cache with the provided UUID and marks the account type as 'google'. A custom JWT is then
    generated with a custom payload and returned in the response.

    Returns:
        - JSON response containing the registration status, a message, and the custom JWT token.
        - HTTP status code 200 for a successful registration, 400 if required parameters are missing, or 503 if OAuth2 is not enabled.

    Request parameters (in request body as JSON):
        - token (str): The Google JWT token for authentication.
        - payload (dict, optional): Additional payload data describing a DKLs session for the user.
        - uuid (str): The unique identifier for the user.

    Example response:
        {
            "status": "OK",
            "message": "User is registered.",
            "token": "custom_jwt_token"
        }
    """
    if not use_firebase:
        return (
            jsonify(
                {
                    "error": "OAuth2 not enabled on this server",
                }
            ),
            503,
        )

    logger.info(f"Registering a Google JWT")

    # Extract token, payload, and uuid from the request
    token = request.json.get("token")
    payload = request.json.get("payload", None)
    uuid = request.json.get("uuid")

    logger.info(f"Got a request from user {uuid}")

    if token is None:
        return jsonify({"error": "No token provided"}), 400

    if uuid is None:
        return jsonify({"error": "No UUID provided"}), 400

    if payload is None:
        payload = {}

    # We're creating an account - if one already exists, return an error
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM Accounts WHERE userid = %s", (uuid,))
    user_record = cursor.fetchone()

    if user_record:
        cursor.close()
        conn.close()
        logger.info(f"User ID {uuid} already exists")
        return jsonify({"error": "User already exists"}), 400

    logger.info(f"User ID {uuid} does not exist. Creating new account")

    logger.info(f"Checking token: {token}")
    decoded_token = auth.verify_id_token(token, firebase_app)
    logger.info("Verified given token OK")
    logger.info(decoded_token)

    # Associate the user ID with the Google account user ID
    cursor.execute(
        "INSERT INTO Accounts (userid, account_type) VALUES (%s, %s)",
        (uuid, "google"),
    )
    cursor.execute(
        "INSERT INTO OAuth2 (userid, provider, provider_uid) VALUES (%s, %s, %s)",
        (uuid, "google", decoded_token["user_id"]),
    )
    conn.commit()

    # Generate new token with custom payload
    custom_token = jwt.encode(
        {
            "user_id": uuid,
            "setup_string": json.dumps(payload),
            "exp": datetime.utcnow() + timedelta(seconds=payload.get("timeout", 30)),
        },
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )

    return (
        jsonify(
            {
                "status": "OK",
                "message": "User is registered.",
                "token": custom_token,
            }
        ),
        200,
    )


@app.route("/verify_google_jwt", methods=["POST"])
def verify_google_jwt():
    """
    Handles the POST request to verify a user with a Google JWT (JSON Web Token).

    This endpoint is used for verifying an existing user account using a Google JWT. It checks if OAuth2 is enabled on the server and
    returns an error if it's not. The function expects a token, payload, and UUID in the request body. It verifies the token with Firebase
    and checks if the provided UUID matches the one associated with the Google account. If the verification is successful, a custom JWT
    token is generated with the given payload and returned in the response.

    Returns:
        - JSON response containing the verification status, a message, and the custom JWT token.
        - HTTP status code 200 for successful verification, 400 if the UUID is not recognized or does not match, or 503 if OAuth2 is not enabled.

    Request parameters (in request body as JSON):
        - token (str): The Google JWT token for authentication.
        - payload (dict): Additional payload data describing a DKLs session for the user.
        - uuid (str): The unique identifier for the user.

    Example response:
        {
            "status": "OK",
            "message": "User is authenticated.",
            "token": "custom_jwt_token"
        }
    """
    if not use_firebase:
        return (
            jsonify(
                {
                    "error": "OAuth2 not enabled on this server",
                }
            ),
            503,
        )
    logger.info(f"Verifying a Google JWT")

    # Extract token, payload, and uuid from the request
    token = request.json.get("token")
    payload = request.json.get("payload")
    uuid = request.json.get("uuid")

    logger.info(f"Got a request from user {uuid}")

    # If verification fails, return an error response
    logger.info(f"Checking token: {token}")
    decoded_token = auth.verify_id_token(token, firebase_app)
    logger.info("Verified given token OK")
    logger.info(decoded_token)

    # Is this user already associated with this google account?

    con = get_db_connection()
    cursor = con.cursor(dictionary=True)

    cursor.execute(
        "SELECT provider_uid FROM OAuth2 WHERE userid = %s AND provider = %s",
        (uuid, "google"),
    )
    row = cursor.fetchone()
    cursor.close()
    con.close()
    known_user_id = row["provider_uid"] if row else None

    if known_user_id is None:
        logger.info("User ID not recognized for this user")
        return jsonify({"error": "User ID not recognized"}), 400
    if known_user_id != decoded_token["user_id"]:
        logger.info(
            "User ID does not match: {} != {}".format(
                known_user_id, decoded_token["user_id"]
            )
        )
        return jsonify({"error": "User ID does not match"}), 400
    logger.info(f"User ID {uuid} matches Google account {decoded_token['user_id']}")

    # Generate new token with custom payload
    custom_token = jwt.encode(
        {
            "user_id": uuid,
            "setup_string": json.dumps(payload),
            "exp": datetime.utcnow() + timedelta(seconds=payload.get("timeout", 30)),
        },
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )

    return (
        jsonify(
            {
                "status": "OK",
                "message": "User is authenticated.",
                "token": custom_token,
            }
        ),
        200,
    )


@app.route("/get_account", methods=["POST"])
def get_account():
    """
    Handles the POST request to check if the given UUID is associated with a user account and returns its authentication type and public keys.

    This endpoint accepts a UUID as a query string parameter. It checks if the UUID is associated with a user account authenticated with Passkeys or Google.
    It first verifies if a UUID is provided in the query string and returns an error if it is missing. Then, it checks the cache for the account type and public keys
    associated with the UUID. If the UUID is not recognized, it is marked as 'unknown'.

    Returns:
        - JSON response containing the 'account_type' (a string) and a list of 'public_keys' associated with the user.
        - HTTP status code 200 for a successful response, or 400 if no UUID is provided.

    Request parameters:
        - uuid (str): The unique identifier of the user account.

    Example response:
        {
            "account_type": "Passkeys",
            "public_keys": ["key1Hex", "key2Hex"]
        }
    """
    # The UUID is given in the query string
    uuid = request.args.get("uuid")

    if uuid is None:
        return jsonify({"error": "No UUID query string provided"}), 400

    # Check if the user is authenticated with Passkeys
    logger.info(f"Checking if user {uuid} is authenticated with Passkeys or Google")

    con = get_db_connection()
    cursor = con.cursor(dictionary=True)

    cursor.execute(
        "SELECT account_type FROM Accounts WHERE userid = %s",
        (uuid,),
    )
    row = cursor.fetchone()
    account_type = row["account_type"] if row else None

    if account_type is None:
        logger.info("User ID not recognized for this user")
        account_type = "unknown"

    logger.info(f"User ID {uuid} is authenticated with {account_type}")

    # Fetch the public keys associated with this user.
    cursor.execute(
        "SELECT publickey FROM DKLs WHERE userid = %s",
        (uuid,),
    )
    # There may be many public keys associated with this user. Convert them to a list
    public_keys = [row["publickey"] for row in cursor.fetchall()]

    logger.info(f"Got public keys: {public_keys}")

    cursor.close()
    con.close()
    return (
        jsonify({"account_type": account_type, "public_keys": list(public_keys)}),
        200,
    )


@app.route("/", methods=["GET"])
def check():
    return "auth layer ok"


if __name__ == "__main__":
    # The port is defined by the PORT environment variable
    PORT = int(os.environ.get("PORT", 5000))
    HOST = os.environ.get("FLASK_HOST", "::")

    logger.debug("Using host: {}".format(HOST))
    logger.debug("Using port: {}".format(PORT))

    app.run(host=HOST, port=PORT, debug=True)
