from __future__ import print_function, absolute_import, unicode_literals

import argparse
# Import for encoding data as base64.
import base64
import sys
from pprint import pprint

from fido2.client import Fido2Client
# Imports for FIDO2 py-lib.
from fido2.hid import CtapHidDevice

import swagger_client
from swagger_client.rest import ApiException

# create an instance of the API class
api_instance = swagger_client.AuthenticationApi(swagger_client.ApiClient(swagger_client.Configuration()))


# This function is also defined in registration file.
def encodeDataForServer(dataToEncode):
    urlSafeEncodedBytes = base64.urlsafe_b64encode(dataToEncode)
    sEncodedData = str(urlSafeEncodedBytes, "utf-8")

    # Remove padding characters.
    while sEncodedData[-1:] == "=":
        sEncodedData = sEncodedData[:-1]

    return sEncodedData


# This function is also defined in registration file.
def getBytesFromBase64String(sBase64StringToDecode):
    # Check if padding characters are omitted from base64-encoded string.
    iPaddingCharCount = 0
    if len(sBase64StringToDecode) % 4 != 0:
        # Determine how many padding characters to concatenate.
        if (len(sBase64StringToDecode) + 1) % 4 == 0:
            # Only missing one padding character.
            iPaddingCharCount = 1
        else:
            # Must be missing two padding characters.
            iPaddingCharCount = 2

    # Concatenate appropriate number of padding characters to base64-encoded string.
    if iPaddingCharCount > 0:
        sBase64StringToDecode += "="
    if iPaddingCharCount == 2:
        sBase64StringToDecode += "="

    # Convert base64 string to decoded bytes.
    encodedData = sBase64StringToDecode.encode("utf-8")
    decodedBytes = base64.urlsafe_b64decode(encodedData)

    # Return decoded bytes.
    return decodedBytes


def initFidoAuthentication(sUserName, sOTP):
    # Create body for API.
    # For server JSON parser, it needs single quotes in JSON string.
    body = "{'name': " + sUserName + ",'password': " + sOTP + "'}"
    try:
        # Generate a authentication FIDO challenge for the client
        api_response = api_instance.start_authentication(body)
        return api_response
    except ApiException as e:
        print("Exception when calling AuthenticationApi->start_authentication: %s\n" % e)


def generateFIDOAuthenticationResponse(sRpId, sChallenge, sCredId):
    use_nfc = False
    # Locate a device.

    dev = next(CtapHidDevice.list_devices(), None)
    if not dev:
        print("No FIDO device found")
        sys.exit(1)

    # Set up a FIDO 2 client using the origin as our FIDO test server.
    client = Fido2Client(dev, "https://chadwickd.uok.ac.uk")

    # Prepare parameters for getAssertion
    challenge = sChallenge

    # Get cred ID as decoded bytes.
    decodedCredIdBytes = getBytesFromBase64String(sCredId)
    allow_list = [{"type": "public-key", "id": decodedCredIdBytes}]

    # Prompt for Authenticator PIN if needed
    # pin = None
    # if client.info.options.get("clientPin"):
    #     pin = getpass("Please enter PIN: ")
    # else:
    #     print("No pin")

    # Authenticate the credential
    if not use_nfc:
        print("\nTouch your authenticator device now...\n")

    print("£££££££££££££££££££££££££££££££££££££££££££££££")
    assertions, client_data = client.get_assertion(sRpId, challenge, allow_list, pin=pin)
    # pprint(assertions)
    # pprint(client_data)
    return assertions, client_data


def createAuthenticationResponseJSON(authenticationRequest, sCredId, sUserId):
    assertions, client_data = generateFIDOAuthenticationResponse(
        authenticationRequest.public_key_credential_request_options.rp_id,
        authenticationRequest.public_key_credential_request_options.challenge, sCredId)
        # authenticationRequest.public_key_credential_request_options.allow_credentials[0]["id"])

    # Use values from authenticator response to create JSON for server to complete authentication operation.
    sAuthResponseJson = "{"
    sAuthResponseJson += "'id':'" + encodeDataForServer(assertions[0].credential["id"]) + "',"
    sAuthResponseJson += "'type':'public-key',"
    sAuthResponseJson += "'response':{"
    sAuthResponseJson += "'authenticatorData':'" + encodeDataForServer(assertions[0].auth_data) + "',"
    sAuthResponseJson += "'clientDataJSON':'" + encodeDataForServer(client_data) + "',"
    sAuthResponseJson += "'signature':'" + encodeDataForServer(assertions[0].signature) + "',"
    sAuthResponseJson += "'userHandle':'" + sUserId + "'},"
    sAuthResponseJson += "'clientExtensionResults':{}"
    sAuthResponseJson += "}"

    return sAuthResponseJson


def finishAuthenticationOperation(authenticationResponseJSON):
    try:
        # Submit a signed challenge for authentication to the server.
        api_response = api_instance.finish_authentication(authenticationResponseJSON)
        # pprint(api_response)

        return api_response
    except ApiException as e:
        print("Exception when calling AuthenticationApi->finish_authentication: %s\n" % e)


if __name__ == '__main__':

    pin = "1234"

    authenticationRequest = initFidoAuthentication("ruhma@metrarc.com", "Ruhma Tahir")
    print(type(authenticationRequest))
    print(authenticationRequest)
    print("=========================================================================================")

    # Need userid for Authentication workflow, maybe from IdP or provided by VC Holder DB? Must have been used
    # for the Registration of the user beforehand
    sUserId = "8wKDhbEfbJ9yOOwKWzJRZjFXI5jStID28qegzRtA2sSntwRzIy458rOJydivm0lLZoGSPqdwNaLKKJ6PL9CLCg"

    # Need Public Key ID for Authentication workflow, probably from VC Holder DB? Must have
    # been sent as part of the Attestation Object in the Registration workflow before
    sCredId = "jxY5s-CaM-8U8Gei_sEdK9msnMg2zS73CfJ75gYUxNnsuSV1wP9kGM8MbD7eg7oTSRdj_GxCBNrm6k5SMM127A"

    sAuthResponseJson = createAuthenticationResponseJSON(authenticationRequest, sCredId, sUserId)
    pprint(sAuthResponseJson)

    # serverResult = finishAuthenticationOperation(sAuthResponseJson)
    # print(type(serverResult))
    # pprint(serverResult)
    #
    # if serverResult.status == "ok":
    #     print("Authentication success.")
    # else:
    #     print("Authentication failed.")
