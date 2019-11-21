from __future__ import print_function, absolute_import, unicode_literals

import argparse
import base64
import sys
from pprint import pprint
import cbor
from fido2.client import Fido2Client
from fido2.hid import CtapHidDevice
import startRegistration
import swagger_client
from swagger_client.rest import ApiException

# create an instance of the API class
api_instance = swagger_client.RegistrationApi(swagger_client.ApiClient(swagger_client.Configuration()))


def encodeDataForServer(dataToEncode):
    urlSafeEncodedBytes = base64.urlsafe_b64encode(dataToEncode)
    sEncodedData = str(urlSafeEncodedBytes, "utf-8")

    # Remove padding characters.
    while sEncodedData[-1:] == "=":
        sEncodedData = sEncodedData[:-1]

    return sEncodedData


def generateValidAttestationObject(authData):
    # Create object.
    testObj = {
        "fmt": "none",
        "attStmt": {},
        "authData": authData
    }

    # CBOR encode object.
    cborData = cbor.dumps(testObj)

    # Base64-encode cborData.
    attestationObject = encodeDataForServer(cborData)

    return attestationObject


def getBytesFromBase64String(sBase64StringToDecode):
    # Check if padding characters are omitted from base64-encoded string
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


def generateFIDORegistrationResponse(sRpId, sRpName, sUserId, sUserName, sChallenge, pubKeyCredParams):
    use_nfc = False
    # Locate a device.

    dev = next(CtapHidDevice.list_devices(), None)
    if dev is not None:
        print("Use USB HID channel.")
    else:
        try:
            from fido2.pcsc import CtapPcscDevice
            dev = next(CtapPcscDevice.list_devices(), None)
            print("Use NFC channel.")
            use_nfc = True
        except Exception as e:
            print("NFC channel search error:", e)
    if not dev:
        print("No FIDO device found")
        sys.exit(1)

    # Set up a FIDO 2 client using the origin as our FIDO test server.
    client = Fido2Client(dev, "https://chadwickd.uok.ac.uk")

    # Prepare parameters for make_credential().
    rp = {"id": sRpId, "name": sRpName}

    # Set request details for generating response from authenticator.
    # Get user ID as decoded bytes.
    # Printing user ID here as need to pass it back with authentication response.
    print("User ID: " + sUserId)
    decodedUserIdBytes = getBytesFromBase64String(sUserId)
    user = {"id": decodedUserIdBytes, "name": sUserName}
    algo = pubKeyCredParams[0]["alg"]  # ES256/-7
    challenge = sChallenge

    # Prompt for Authenticator PIN if needed
    # pin = None
    # if client.info.options.get("clientPin"):
    #     pin = getpass("Please enter PIN: ")
    # else:
    #     print("No pin")

    # Create a credential.
    if not use_nfc:
        print("\nTouch your authenticator device now...\n")

    attestation_object, client_data = client.make_credential(rp, user, challenge, algos=[algo], pin=pin)

    return attestation_object, client_data


def createRegistrationResponseJSON(registrationRequest):
    # Use registration request form server to generate a response with the authenticator.
    attestation_object, client_data = generateFIDORegistrationResponse(registrationRequest.rp.id,
                                                                       registrationRequest.rp.name,
                                                                       registrationRequest.user.id,
                                                                       registrationRequest.user.name,
                                                                       registrationRequest.challenge,
                                                                       registrationRequest.pub_key_cred_params)

    # Format data before sending to server.
    attestationObject = generateValidAttestationObject(attestation_object.auth_data)

    # Base64-encode clientDataJSON.
    clientDataJson = encodeDataForServer(client_data)

    # Base64-encode credential ID.
    sCredId = encodeDataForServer(attestation_object.auth_data.credential_data.credential_id)

    # Create JSON registration response to send back to server.
    sRegResponse = "{'id':'" + sCredId + "','type':'public-key', 'response':{'attestationObject':'" + attestationObject + "','clientDataJSON':'" + clientDataJson + "'},'clientExtensionResults':{}}"
    return sRegResponse


def finishRegistrationOperation(registrationResponseJSON):
    try:
        # Call the API for creating a FIDO challenge for register operation.
        api_response = api_instance.finish_registration(registrationResponseJSON)
        return api_response
    except ApiException as e:
        print("Exception when calling TestApi->finish_registration: %s\n" % e)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("name", help="User's email address", default="ruhma@metrarc.com")
    parser.add_argument("displayName", help="User's Display Name", default="Ruhma Tahir")
    parser.add_argument("pin", help="Authenticator's PIN", default="1234")
    args = parser.parse_args()

    pin = args.pin

    registrationRequest = startRegistration.initFidoRegistration(args.name, args.displayName)

    # createRegistrationResponseJSON function should actually run on VCHolder and return the Attestation Object
    sRegResponse = createRegistrationResponseJSON(registrationRequest)
    print(type(sRegResponse))
    print(sRegResponse)
    serverResult = finishRegistrationOperation(sRegResponse)
    if serverResult.status == "ok":
        print("Registration success.")
    else:
        print("Registration failed.")
