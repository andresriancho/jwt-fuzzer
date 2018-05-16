from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt


def header_x5u_remove(jwt_string):
    """
    If the header looks like:
        {
            "x5u": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    try:
        del header['x5u']
    except:
        return
    else:
        yield encode_jwt(header, payload, signature)


def header_x5u_dev_null(jwt_string):
    """
    If the header looks like:
        {
            "x5u": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "x5u": "/dev/null",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'x5u' not in header:
        return

    header['x5u'] = '/dev/null'
    yield encode_jwt(header, payload, signature)


def header_x5u_self_reference(jwt_string):
    """
    If the header looks like:
        {
            "x5u": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "x5u": "/./key-1.cer",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'x5u' not in header:
        return

    header['x5u'] = '/./' + header['x5u']
    yield encode_jwt(header, payload, signature)


def header_x5u_url(jwt_string):
    """
    If the header looks like:
        {
            "x5u": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "x5u": "https://localhost/key-1.cer",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'x5u' not in header:
        return

    header['x5u'] = 'http://localhost/' + header['x5u']
    yield encode_jwt(header, payload, signature)


def header_x5u_file_url(jwt_string):
    """
    If the header looks like:
        {
            "x5u": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "x5u": "file://key-1.cer",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'x5u' not in header:
        return

    header['x5u'] = 'file://' + header['x5u']
    yield encode_jwt(header, payload, signature)


def header_x5u_file_url_root(jwt_string):
    """
    If the header looks like:
        {
            "x5u": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "x5u": "file:///",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'x5u' not in header:
        return

    header['x5u'] = 'file:///'
    yield encode_jwt(header, payload, signature)
