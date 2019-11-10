from __future__ import print_function
import swagger_client
from swagger_client.rest import ApiException


# Import for encoding data as base64.
import base64

# Import for parsing JSON.
import json


def testSendMessage():
    bDidApiSucceed = False

    # create an instance of the API class
    api_instance = swagger_client.TestApi(swagger_client.ApiClient(swagger_client.Configuration()))

    body = 'Hello server'  # str |

    try:
        # sends a string to the server
        api_response = api_instance.send_message(body)

        print("Sent message    : ", body)
        print("Received message: ", api_response)

        if api_response == body:
            bDidApiSucceed = True
    except ApiException as e:
        print("Exception when calling TestApi->send_message: %s\n" % e)

    return bDidApiSucceed


def testSendBase64Url():
    bDidApiSucceed = False

    # create an instance of the API class
    api_instance = swagger_client.TestApi(swagger_client.ApiClient(swagger_client.Configuration()))

    sOriginalData = "bEVJZGWheX4eh-9JcjEdX_tGNub5tqDmNA7iHeKGAfwJ-jsJ27qOOtTy90noX7QL5chjfn8Rj9rEatYPze_RKg=="
    # Create base64-encoded data to send to server.
    strBytes = bytes(sOriginalData, "utf-8")
    bodyBytes = base64.urlsafe_b64encode(strBytes)
    sBodyBytes = bodyBytes.decode("utf-8")

    # Create JSON string.
    sJsonWithBase64Data = "{\"clientMessage\": \"" + sBodyBytes + "\"}"

    try:
        # send a Base64URL encoded executable to the server
        api_response = api_instance.send_base64_url(sJsonWithBase64Data)
        # pprint(api_response)

        # Format response to replace single quotes with double quotes for valid JSON.
        formatted_api_response = api_response.replace("'", "\"")

        # Parse JSON response.
        api_response_dict = json.loads(formatted_api_response)

        # Verify initial binary data sent to server matches response.
        decoded_bytes = base64.urlsafe_b64decode(api_response_dict["clientMessage"])
        sData = decoded_bytes.decode("utf-8")

        print("Sent code    : ", sOriginalData)
        print("Received code: ", sData)
        if sData == sOriginalData:
            bDidApiSucceed = True
    except ApiException as e:
        print("Exception when calling TestApi->send_base64_url: %s\n" % e)

    return bDidApiSucceed


if __name__ == '__main__':
    if testSendMessage():
        print("'send_message' API test passed.")
    else:
        print("'send_message' API test failed.")

    if testSendBase64Url():
        print("'send_base64_url' API test passed.")
    else:
        print("'send_base64_url' API test failed.")
