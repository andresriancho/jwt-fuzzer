from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt


def payload_remove(jwt_string):
    """
    Completely removes the payload

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    return encode_jwt(header, '', signature)
