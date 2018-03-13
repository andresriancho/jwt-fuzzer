from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt


def header_typ_empty(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "HS256",
          "typ": ""
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['typ'] = ''
    yield encode_jwt(header, payload, signature)


def header_typ_remove(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "HS256",
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    try:
        del header['typ']
    except KeyError:
        # Some JWT implementations, such as the one used by Google, doesn't
        # send the typ header parameter
        return

    yield encode_jwt(header, payload, signature)


def header_typ_null(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "HS256",
          "typ": null
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['typ'] = None
    yield encode_jwt(header, payload, signature)


def header_typ_invalid(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "HS256",
          "typ": "invalid"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['typ'] = 'invalid'
    yield encode_jwt(header, payload, signature)


def header_typ_none(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "HS256",
          "typ": "none"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['typ'] = 'none'
    yield encode_jwt(header, payload, signature)
