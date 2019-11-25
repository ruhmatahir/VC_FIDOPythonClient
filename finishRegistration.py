from __future__ import print_function, absolute_import, unicode_literals


import argparse
import urllib3

import swagger_client
from swagger_client.rest import ApiException

urllib3.disable_warnings()
# create an instance of the API class
api_instance = swagger_client.RegistrationApi(swagger_client.ApiClient(swagger_client.Configuration()))


def finishRegistrationOperation(registrationResponseJSON):
    try:
        # Call the API for creating a FIDO challenge for register operation.
        api_response = api_instance.finish_registration(registrationResponseJSON)
        return api_response
    except ApiException as e:
        print("Exception when calling TestApi->finish_registration: %s\n" % e)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("sRegResponse", help="VCHolder's Attestation Object")
    args = parser.parse_args()

    sRegResponse = args.sRegResponse
    # print(sRegResponse)

    # sRegResponse =

    serverResult = finishRegistrationOperation(sRegResponse)
    if serverResult.status == "ok":
        print("Registration success")
    else:
        print("Registration failed")
