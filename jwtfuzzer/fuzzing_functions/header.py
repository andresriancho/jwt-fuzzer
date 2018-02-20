from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt


def header_remove(jwt_string):
    """
    Completely removes the header

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    yield encode_jwt('', payload, signature)


def header_is_a_list(jwt_string):
    """
    Change header type to a list: boom!

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    yield encode_jwt([], payload, signature)