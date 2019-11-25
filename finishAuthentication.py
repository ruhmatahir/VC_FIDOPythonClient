from __future__ import print_function, absolute_import, unicode_literals

import argparse
import urllib3
import swagger_client
from swagger_client.rest import ApiException

# create an instance of the API class
api_instance = swagger_client.AuthenticationApi(swagger_client.ApiClient(swagger_client.Configuration()))
urllib3.disable_warnings()


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
    parser.add_argument("sAuthResponseJson", help="VCHolder's Assertion Object")
    args = parser.parse_args()

    sAuthResponseJson = args.sAuthResponseJson

    serverResult = finishAuthenticationOperation(sAuthResponseJson)

    if serverResult.status == "ok":
        print("Authentication success")
    else:
        print("Authentication failed")
