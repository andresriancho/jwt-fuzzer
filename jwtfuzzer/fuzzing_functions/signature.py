from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt


def signature_remove(jwt_string):
    """
    Completely removes the signature

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    return encode_jwt(header, payload, '')


def signature_zero(jwt_string):
    """
    0x00

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    return encode_jwt(header, payload, '\0')


def signature_reverse(jwt_string):
    """
    Reverse the signature string

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    signature = signature[::-1]
    return encode_jwt(header, payload, signature)
