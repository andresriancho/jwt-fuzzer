from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt


def header_jku_remove(jwt_string):
    """
    If the header looks like:
        {
            "jku": "key-1.cer",
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
        del header['jku']
    except:
        return
    else:
        yield encode_jwt(header, payload, signature)


def header_jku_dev_null(jwt_string):
    """
    If the header looks like:
        {
            "jku": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "jku": "/dev/null",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'jku' not in header:
        return

    header['jku'] = '/dev/null'
    yield encode_jwt(header, payload, signature)


def header_jku_self_reference(jwt_string):
    """
    If the header looks like:
        {
            "jku": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "jku": "/./key-1.cer",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'jku' not in header:
        return

    header['jku'] = '/./' + header['jku']
    yield encode_jwt(header, payload, signature)


def header_jku_url(jwt_string):
    """
    If the header looks like:
        {
            "jku": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "jku": "https://localhost/key-1.cer",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'jku' not in header:
        return

    header['jku'] = 'http://localhost/' + header['jku']
    yield encode_jwt(header, payload, signature)


def header_jku_file_url(jwt_string):
    """
    If the header looks like:
        {
            "jku": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "jku": "file://key-1.cer",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'jku' not in header:
        return

    header['jku'] = 'file://' + header['jku']
    yield encode_jwt(header, payload, signature)


def header_jku_file_url_root(jwt_string):
    """
    If the header looks like:
        {
            "jku": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "jku": "file:///",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'jku' not in header:
        return

    header['jku'] = 'file:///'
    yield encode_jwt(header, payload, signature)
