from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt


def header_alg_empty(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "",
          "typ": "JWT"
        }

    :param jwt_string: The JWT as a string
    :param output: The file where the modified JWT is written to
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['alg'] = ''
    return encode_jwt(header, payload, signature)


def header_alg_remove(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "typ": "JWT"
        }

    :param jwt_string: The JWT as a string
    :param output: The file where the modified JWT is written to
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    del header['alg']
    return encode_jwt(header, payload, signature)


def header_alg_null(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "typ": "JWT"
          "alg": null,
        }

    :param jwt_string: The JWT as a string
    :param output: The file where the modified JWT is written to
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['alg'] = None
    return encode_jwt(header, payload, signature)


def header_alg_invalid(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "typ": "JWT"
          "alg": "invalid",
        }

    :param jwt_string: The JWT as a string
    :param output: The file where the modified JWT is written to
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['alg'] = 'invalid'
    return encode_jwt(header, payload, signature)