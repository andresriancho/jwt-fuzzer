from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt


def payload_remove(jwt_string):
    """
    Completely removes the payload

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    yield encode_jwt(header, '', signature)


def payload_remove_key_value(jwt_string):
    """
    Removes the key/value pairs stored in the payload.

    :param jwt_string: The JWT as a string
    :yield: The different JWT as string
    """
    header, payload, signature = decode_jwt(jwt_string)

    if isinstance(payload, dict):
        for key in payload:
            payload_copy = payload.copy()
            del payload_copy[key]
            yield encode_jwt(header, payload_copy, signature)

    if isinstance(payload, list):
        for item in payload:
            payload_copy = payload[:]
            payload_copy.pop(item)
            yield encode_jwt(header, payload_copy, signature)


def payload_add_space_to_value(jwt_string):
    """
    Adds a space at the end of the value stored in the payload.

    :param jwt_string: The JWT as a string
    :yield: The different JWT as string
    """
    header, payload, signature = decode_jwt(jwt_string)

    if isinstance(payload, dict):
        for key, value in payload.iteritems():
            if not isinstance(value, basestring):
                continue

            payload_copy = payload.copy()
            payload_copy[key] = value + ' '
            yield encode_jwt(header, payload_copy, signature)

    if isinstance(payload, list):
        for i, item in enumerate(payload):
            if not isinstance(item, basestring):
                continue

            payload_copy = payload[:]
            payload_copy[i] = item + ' '
            yield encode_jwt(header, payload_copy, signature)
