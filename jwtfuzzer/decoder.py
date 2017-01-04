import collections
import base64
import json
import sys


def base64url_decode(input):
    rem = len(input) % 4

    if rem > 0:
        input += b'=' * (4 - rem)

    return base64.urlsafe_b64decode(input)


def decode_jwt(jwt_string):
    """
    Decodes a JWT into its parts.

    :return: Header, payload and signature. Header and payload are both returned as python dictionaries
             which should be easier to modify.
    """
    try:
        header, payload, signature = jwt_string.split('.')
    except ValueError:
        print('Invalid input, the JWT contains more than two dots.')
        sys.exit(1)

    try:
        header = base64url_decode(header)
    except:
        print('Invalid input, the JWT contains invalid base64 encoded data in the header.')
        sys.exit(1)

    try:
        payload = base64url_decode(payload)
    except:
        print('Invalid input, the JWT contains invalid base64 encoded data in the payload.')
        sys.exit(1)

    try:
        signature = base64url_decode(signature)
    except:
        print('Invalid input, the JWT contains invalid base64 encoded data in the signature.')
        sys.exit(1)

    try:
        # The object_pairs_hook trick keeps the original parameter ordering
        # http://stackoverflow.com/questions/6921699/can-i-get-json-to-load-into-an-ordereddict-in-python
        header = json.loads(header, object_pairs_hook=collections.OrderedDict)
        payload = json.loads(payload, object_pairs_hook=collections.OrderedDict)
    except:
        print('Invalid input, the JWT contains invalid JSON encoded data.')
        sys.exit(1)

    return header, payload, signature
