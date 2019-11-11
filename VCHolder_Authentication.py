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

    assertions, client_data = client.get_assertion(sRpId, challenge, allow_list, pin=pin)

    return assertions, client_data


def createAuthenticationResponseJSON(authenticationRequest):
    assertions, client_data = generateFIDOAuthenticationResponse(
        authenticationRequest.public_key_credential_request_options.rp_id,
        authenticationRequest.public_key_credential_request_options.challenge,
        authenticationRequest.public_key_credential_request_options.allow_credentials[0]["id"])

    # Use values from authenticator response to craete JSON for server to complete authentiction operation.
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
    parser = argparse.ArgumentParser()
    parser.add_argument("name", help="User's email address", default="ruhma@metrarc.com")
    parser.add_argument("password", help="User's password", default="password")
    parser.add_argument("uid", help="User's ID",
                        default="Pjhl1f9Rtk02VgsMxj3jqGed0bJXLGZyKvFi_AUKC5G7ddknPcaNAO5Yb1J09sE72QiU0401PhX4kt487A1MVg")
    parser.add_argument("pin", help="Authenticator's PIN", default="1234")
    args = parser.parse_args()

    pin = args.pin

    body = "{'name': " + args.name + ",'password': " + args.password + "'}"

    # Value taken from registration print, needed for server to complete authentication operation.
    # sUserId = "J9zWHhSN46wZEACIF4voW67mgZE3myujv0dy2lHtx5oz-iLoaSMyqzNN9vkwy6m_YH3gn6xjvzcbavruYiYhxg"
    sUserId = args.uid
    try:
        # Generate a authentication FIDO challenge for the client
        api_response = api_instance.start_authentication(body)
        pprint(api_response)
    except ApiException as e:
        print("Exception when calling AuthenticationApi->start_authentication: %s\n" % e)

    sAuthResponseJson = createAuthenticationResponseJSON(api_response)
    serverResult = finishAuthenticationOperation(sAuthResponseJson)

    if serverResult.status == "ok":
        print("Authentication success.")
    else:
        print("Authentication failed.")
