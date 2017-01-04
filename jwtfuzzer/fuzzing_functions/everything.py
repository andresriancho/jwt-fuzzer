from jwtfuzzer.encoder import encode_jwt


def all_empty(jwt_string):
    """
    Completely removes all fields

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return encode_jwt('', '', '')


def multiple_dots(jwt_string):
    """
    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return '..................'
