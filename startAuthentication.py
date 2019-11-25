from __future__ import print_function, absolute_import, unicode_literals

import argparse
import swagger_client
from swagger_client.rest import ApiException

# create an instance of the API class
api_instance = swagger_client.AuthenticationApi(swagger_client.ApiClient(swagger_client.Configuration()))


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


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("name", help="User's email address", default="ruhma@metrarc.com")
    parser.add_argument("otp", help="OTP", default="1234567890")

    args = parser.parse_args()

    authenticationRequest = initFidoAuthentication(args.name, args.otp)
    # print("\nstart_authentication -> PublicKeyCredentialsRequestOption:")
    print(authenticationRequest)
