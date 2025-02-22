# DKLs23 authorisation layer

The DKLs23 project has a Rust compute layer. However, this does not include much in the way of user authentication - that is handled by this Flask server. There are currently two methods of user verification that have been implemented, Passkeys (a.k.a. webauthn), and OAuth2. Note that the latter leverages Firebase as a "one-stop shop" for different OAuth2 providers, so will require some additional setup with that service.

### Firebase configuration

Finally, you also need to supply a Firebase `serviceAccountKey.json` file to this folder. The file path to this is given by the `FIREBASE_CERTIFICATE` variable. To get such a key, go to the [Service Accounts page](https://console.firebase.google.com/project/_/settings/serviceaccounts/adminsdk?_gl=1*1qzrtd2*_ga*NDI4NzEwOS4xNzAyNTU4MTQz*_ga_CW55HF8NVT*MTcwMjU1ODE0My4xLjEuMTcwMjU1ODMxNi41Ni4wLjA.) on firebase, and click _Generate New Private Key_, then _Generate Key_. Download the JSON file, and place it somewhere that the authorisation server can reach it. By default, the code looks for the file `serviceAccountKey.json` in the same directory as the `node_server.py` file.

An example `serviceAccountKey.json` file is provided for internal usage [here](https://drive.google.com/file/d/1vohwmJoF7qawrz8yVyvYGQ2YWj9M7pN7/view?usp=sharing), and the corresponding frontend firebase configuration is given [here](https://drive.google.com/file/d/1MisME5zntRY9iLxZ0CBu_puMqXDf21lK/view?usp=sharing)

Note that you will also need the frontend to be validated with a counterpart configuration, documented in the relevant [README](../demo_page/README.md).

## Endpoints

### 1. Issue Registration Challenge

- **URL:** `/issue_passkeys_challenge`
- **Method:** `GET`
- **Description:** This endpoint is used to issue a challenge that the client must solve as part of the registration process.

**Response:**

- `200 OK` if successful along with a JSON object containing the challenge: `{"challenge": "string"}`.

### 2. Verify Registration

- **URL:** `/verify_passkeys_registration`
- **Method:** `POST`
- **Description:** This endpoint is used to verify the client's registration response. This involves verifying that the client correctly signed the challenge issued earlier and that the registration data is valid.

**Request Parameters:**

- `raw_credential` (JSON object): The raw registration credential object returned by the client, issued by WebAuthn c.f. `navigator.credentials.create()`.
- `challenges` (List of strings): A list of challenges that the client is claiming to have used.
- `origin` (string): The origin URL from which the request is being made.
- `rp_id` (string): The Relying Party Identifier for which the registration is being performed.

**Response:**

- `200 OK` if the registration is verified, along with a JSON object containing the status, message, credential_id, and credential.
- `400 Bad Request` if the registration is not verified, along with an error message.

### 3. Issue Authentication Challenge

- **URL:** `/issue_authentication_challenge`
- **Method:** `GET`
- **Description:** This endpoint is used to issue a challenge that the client must sign as part of the authentication process.

**Request Parameters:**

- `credential_id` (string): The credential ID that the client is authenticating with.

**Response:**

- `200 OK` if successful along with a JSON object containing the challenge.
- `400 Bad Request` if no credential ID is provided or if the credential ID is not recognized, along with an error message.

### 4. Verify Authentication

- **URL:** `/verify_authentication`
- **Method:** `POST`
- **Description:** This endpoint is used to verify the client's authentication response. This involves verifying that the client correctly signed the challenge issued earlier and that the authentication data is valid.

**Request Parameters:**

- `setup` (string): The setup string used to generate the challenge for authentication. JSON, which should contain a dictionary of challenges under the `nonce` key.
- `rp_id` (string): The Relying Party Identifier for which the authentication is being performed.
- `origin` (string): The origin URL from which the request is being made.
- `credential_id` (string): The credential ID that the client is authenticating with.
- `assertion` (JSON object): The raw assertion object returned by the client, c.f. `navigator.credentials.get()`.

**Response:**

- `200 OK` if the authentication is verified, along with a JSON object containing the status, message, and verification data.
- `400 Bad Request` if the authentication is not verified, along with an error message.

### 5. Register with Google JWT

- **URL:** `/register_google_jwt`
- **Method:** `POST`
- **Description:** This endpoint is used to register a new user account using a Google JSON Web Token (JWT). It checks if OAuth2 is enabled on the server and, if not, returns an error. The function expects a token, payload, and UUID in the request body. It verifies the token with Firebase, registers the user in the cache with the provided UUID, and marks the account type as 'google'. A custom JWT is generated which encodes the setup string, user ID, and token expiry date, and this returned to the caller.

**Request Parameters:**

- `token` (string): The Google JWT token for authentication.
- `payload` (dictionary, optional): Additional payload data describing a DKLs session for the user.
- `uuid` (string): The unique identifier for the user.

**Response:**

- `200 OK` if the registration is successful, along with a JSON object containing the registration status, message, and custom JWT token.
- `400 Bad Request` if required parameters are missing.
- `503 Service Unavailable` if OAuth2 is not enabled on the server.

### 6. Verify with Google JWT

- **URL:** `/verify_google_jwt`
- **Method:** `POST`
- **Description:** This endpoint is used for verifying an existing user account using a Google JWT. It checks if OAuth2 is enabled on the server and returns an error if it's not. The function expects a token, payload, and UUID in the request body. It verifies the token with Firebase and checks if the provided UUID matches the one associated with the Google account. If verification is successful, a custom JWT token is generated that encodes the given payload and is returned to the user.

**Request Parameters:**

- `token` (string): The Google JWT token for authentication.
- `payload` (dictionary): Additional payload data describing a DKLs session for the user.
- `uuid` (string): The unique identifier for the user.

**Response:**

- `200 OK` if the verification is successful, along with a JSON object containing the verification status, message, and custom JWT token.
- `400 Bad Request` if the UUID is not recognized or does not match.
- `503 Service Unavailable` if OAuth2 is not enabled on the server.

## Server Objects and Data Structures

These are implemented in the most simple possible way. Realistically, this should be a persistent database for the `CREDENTIALS`, and a cache for the `REG_CHALLENGES`.

- `CREDENTIALS`: A dictionary that stores the credentials of registered users, keyed by the credential ID.

- `REG_CHALLENGES`: A list that stores the challenges issued for the registration process.

# Frontend Documentation

## Overview

This frontend page serves a script used to interact with a WebAuthn backend service for user registration and login. It communicates with the backend via RESTful API calls to facilitate the registration and authentication processes to multiple servers at the same time.

## Functions

### handleRegister()

This asynchronous function handles the user registration process.

1. **Fetching Node Server URLs**: It gets the URLs of the node servers from the HTML input elements and validates them.

2. **Fetching Registration Challenges**: For each node server, it sends a GET request to the `/issue_passkeys_challenge` endpoint to fetch challenges. It then sorts, concatenates, and hashes these challenges to create a final challenge.

3. **Credential Creation**: It creates WebAuthn credentials using the browser's `navigator.credentials.create` method. This is where the user would interact with their authenticator (e.g., using a security key, biometric input, etc.).

4. **Verifying Registration with Nodes**: For each node server, it sends the credentials and the final challenge to the `/verify_passkeys_registration` endpoint using a POST request. The node server will verify the registration.

5. **Storing Credentials**: If the registration is successful and verified by all nodes, the credential data is stored locally for later use.

6. **Displaying Registration Status**: Depending on the success of the registration process, it updates the UI elements accordingly.

### handleLogin()

This asynchronous function handles the user login process.

1. **Fetching Node Server URLs**: It gets the URLs of the node servers from the HTML input elements and validates them.

2. **Fetching Authentication Challenges**: Similar to the registration process, it sends a GET request to each node server's `/issue_authentication_challenge` endpoint to fetch challenges.

3. **Credential Request Options**: It prepares credential request options required for the WebAuthn API, including setting the challenge (which is the hash of the setup JSON, and includes the node-issued challenges) and allowing credentials.

4. **Authentication Assertion**: It creates an authentication assertion using the browser's `navigator.credentials.get` method. The user would authenticate using their authenticator at this step.

5. **Verifying Authentication with Nodes**: For each node server, it sends the assertion and the final challenge to the `/verify_authentication` endpoint using a POST request. The node server will verify the login.

6. **Displaying Authentication Status**: Depending on the success of the authentication process, it updates the UI elements accordingly.
