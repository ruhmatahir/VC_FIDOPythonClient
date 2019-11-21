from __future__ import print_function, absolute_import, unicode_literals

import argparse
import swagger_client
from swagger_client.rest import ApiException

# create an instance of the API class
api_instance = swagger_client.RegistrationApi(swagger_client.ApiClient(swagger_client.Configuration()))


def initFidoRegistration(sUsername, sDisplayName):
    # Create body for API.
    # For server JSON parser, it needs single quotes in JSON string.
    body = "{'username':'" + sUsername + "','displayName':'" + sDisplayName + "'}"

    try:
        # Call the API for creating a FIDO challenge for register operation.
        api_response = api_instance.start_registration(body)
        return api_response
    except ApiException as e:
        print("Exception when calling TestApi->start_registration: %s\n" % e)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("name", help="User's email address", default="ruhma@metrarc.com")
    parser.add_argument("displayName", help="User's Display Name", default="Ruhma Tahir")
    args = parser.parse_args()

    registrationRequest = initFidoRegistration(args.name, args.displayName)
    print(type(registrationRequest))
    print(registrationRequest)

