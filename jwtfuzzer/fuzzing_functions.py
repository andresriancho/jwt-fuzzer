from .decoder import decode_jwt
from .encoder import encode_jwt


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
