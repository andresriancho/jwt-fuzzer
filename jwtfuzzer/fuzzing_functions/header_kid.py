from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt


def header_kid_empty(jwt_string):
    """
    If the header looks like:
        {
          "alg": "RS256",
          "kid": "ac2b63faefcf8362f4c528e7c78433879387016b"
        }

    The result will look like:
        {
          "alg": "RS256",
          "kid": ""
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['kid'] = ''
    yield encode_jwt(header, payload, signature)


def header_kid_remove(jwt_string):
    """
    If the header looks like:
        {
          "alg": "RS256",
          "kid": "ac2b63faefcf8362f4c528e7c78433879387016b"
        }

    The result will look like:
        {
          "alg": "RS256",
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    try:
        del header['kid']
    except KeyError:
        # When the JWT is signed using hashes, there is no kid
        return

    yield encode_jwt(header, payload, signature)


def header_kid_null(jwt_string):
    """
    If the header looks like:
        {
          "alg": "RS256",
          "kid": "ac2b63faefcf8362f4c528e7c78433879387016b"
        }

    The result will look like:
        {
          "alg": "RS256",
          "kid": null
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['kid'] = None
    yield encode_jwt(header, payload, signature)


def header_kid_invalid(jwt_string):
    """
    If the header looks like:
        {
          "alg": "RS256",
          "kid": "ac2b63faefcf8362f4c528e7c78433879387016b"
        }

    The result will look like:
        {
          "alg": "RS256",
          "kid": "invalid"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['kid'] = 'invalid'
    yield encode_jwt(header, payload, signature)


def header_kid_none(jwt_string):
    """
    If the header looks like:
        {
          "alg": "RS256",
          "kid": "ac2b63faefcf8362f4c528e7c78433879387016b"
        }

    The result will look like:
        {
          "alg": "RS256",
          "kid": "none"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['kid'] = 'none'
    yield encode_jwt(header, payload, signature)


def header_kid_reverse(jwt_string):
    """
    If the header looks like:
        {
          "alg": "RS256",
          "kid": "ac2b63faefcf8362f4c528e7c78433879387016b"
        }

    The result will look like:
        {
          "alg": "RS256",
          "kid": "b61078397833487c7e825c4f2638fcfeaf36b2ca"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    try:
        header['kid'] = header['kid'][::-1]
    except KeyError:
        # When the JWT is signed using hashes, there is no kid
        return

    yield encode_jwt(header, payload, signature)


def header_kid_self_reference(jwt_string):
    """
    If the header looks like:
        {
          "alg": "RS256",
          "kid": "ac2b63faefcf8362f4c528e7c78433879387016b"
        }

    The result will look like:
        {
          "alg": "RS256",
          "kid": "/./b61078397833487c7e825c4f2638fcfeaf36b2ca"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    # When the JWT is signed using hashes, there is no kid
    if 'kid' not in header:
        return

    header['kid'] = '/./' + header['kid']
    yield encode_jwt(header, payload, signature)


def header_kid_file_url(jwt_string):
    """
    If the header looks like:
        {
          "alg": "RS256",
          "kid": "ac2b63faefcf8362f4c528e7c78433879387016b"
        }

    The result will look like:
        {
          "alg": "RS256",
          "kid": "file://b61078397833487c7e825c4f2638fcfeaf36b2ca"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    # When the JWT is signed using hashes, there is no kid
    if 'kid' not in header:
        return

    header['kid'] = 'file://' + header['kid']
    yield encode_jwt(header, payload, signature)
