from __future__ import print_function, absolute_import, unicode_literals

import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# Import for encoding data as base64.
import base64

# Imports for FIDO2 py-lib.
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client
from fido2.attestation import Attestation
from getpass import getpass
import sys

# create an instance of the API class
api_instance = swagger_client.AuthenticationApi( swagger_client.ApiClient( swagger_client.Configuration() ) )

# Value taken from registration print, needed for server to complete authentication operation.
sUserId = "vUpxDa9bdAcS_ZehNtEpt6gVyYP8YrHCf4SJnwsefEB9pFI39Oqa_AclHBX5iba9Q9oodCqbi7iwwqbXBCDn_w"

# This function is also defined in registration file.
def encodeDataForServer( dataToEncode ) :
    urlSafeEncodedBytes = base64.urlsafe_b64encode( dataToEncode )
    sEncodedData = str( urlSafeEncodedBytes, "utf-8" )	

    # Remove padding characters.
    while( sEncodedData[ -1: ] == "=" ) :
        sEncodedData = sEncodedData[ :-1 ]

    return sEncodedData

# This function is also defined in registration file.
def getBytesFromBase64String( sBase64StringToDecode ) :
    # Check if padding characters are omitted from base64-encoded string.
    iPaddingCharCount = 0
    if( len( sBase64StringToDecode ) % 4 != 0 ) :
        # Determine how many padding characters to concatenate.
        if( ( len( sBase64StringToDecode ) + 1 ) % 4 == 0 ) :
            # Only missing one padding character.
            iPaddingCharCount = 1
        else :
            # Must be missing two padding characters.
            iPaddingCharCount = 2

    # Concatenate appropriate number of padding characters to base64-encoded string.
    if( iPaddingCharCount > 0 ) :
        sBase64StringToDecode += "="
    if( iPaddingCharCount == 2 ) :
        sBase64StringToDecode += "="

    # Convert base64 string to decoded bytes.
    encodedData = sBase64StringToDecode.encode( "utf-8" )
    decodedBytes = base64.urlsafe_b64decode( encodedData )

    # Return decoded bytes.
    return decodedBytes

def generateFIDOAuthenticationResponse( sRpId, sChallenge, sCredId ) :
    use_nfc = False
    # Locate a device.

    dev = next(CtapHidDevice.list_devices(), None)
    if not dev:
        print("No FIDO device found")
        sys.exit(1)

    # Set up a FIDO 2 client using the origin as our FIDO test server.
    client = Fido2Client( dev, "https://chadwickd.uok.ac.uk" )

    # Prepare parameters for getAssertion
    challenge = sChallenge
    # Get cred ID as decoded bytes.
    decodedCredIdBytes = getBytesFromBase64String( sCredId )
    allow_list = [ { "type": "public-key", "id": decodedCredIdBytes } ]

    # Set PIN for authenticator.
    pin = "1234"

    # Authenticate the credential
    if not use_nfc:
        print("\nTouch your authenticator device now...\n")

    assertions, client_data = client.get_assertion( sRpId, challenge, allow_list, pin = pin )
    return assertions, client_data

def createAuthenticationResponseJSON( authenticationRequest ) :
    assertions, client_data = generateFIDOAuthenticationResponse( authenticationRequest.public_key_credential_request_options.rp_id, authenticationRequest.public_key_credential_request_options.challenge, authenticationRequest.public_key_credential_request_options.allow_credentials[ 0 ][ "id" ] )

    # Use values from authenticator response to craete JSON for server to complete authentiction operation.
    sAuthResponseJson = "{"
    sAuthResponseJson += "'id':'" + encodeDataForServer( assertions[ 0 ].credential[ "id" ] ) + "',"
    sAuthResponseJson += "'type':'public-key',"
    sAuthResponseJson += "'response':{"
    sAuthResponseJson += "'authenticatorData':'" + encodeDataForServer( assertions[ 0 ].auth_data ) + "',"
    sAuthResponseJson += "'clientDataJSON':'" + encodeDataForServer( client_data ) + "',"
    sAuthResponseJson += "'signature':'" + encodeDataForServer( assertions[ 0 ].signature ) + "',"
    sAuthResponseJson += "'userHandle':'" + sUserId + "'},"
    sAuthResponseJson += "'clientExtensionResults':{}"
    sAuthResponseJson += "}"

    return sAuthResponseJson

def finishAuthenticationOperation( authenticationResponseJSON ) :
    try:
        # Submit a signed challenge for authenication to the server.
        api_response = api_instance.finish_authentication( authenticationResponseJSON )
        # pprint(api_response)

        return api_response
    except ApiException as e:
        print("Exception when calling AuthenticationApi->finish_authentication: %s\n" % e)

if __name__ == '__main__':
    body = "{'name':'test_user_name','password':''}"

    try:
        # Generate a authentication FIDO challenge for the client
        api_response = api_instance.start_authentication(body)
        # pprint(api_response)
    except ApiException as e:
        print("Exception when calling AuthenticationApi->start_authentication: %s\n" % e)

    sAuthResponseJson = createAuthenticationResponseJSON( api_response )
    serverResult = finishAuthenticationOperation( sAuthResponseJson )

    if( serverResult.status == "ok" ) :
        print( "Authentication success." )
    else :
        print( "Authentication failed." )
