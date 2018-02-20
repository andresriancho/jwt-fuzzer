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
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['alg'] = ''
    yield encode_jwt(header, payload, signature)


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
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    del header['alg']
    yield encode_jwt(header, payload, signature)


def header_alg_null(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": null,
          "typ": "JWT"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['alg'] = None
    yield encode_jwt(header, payload, signature)


def header_alg_invalid(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "invalid",
          "typ": "JWT"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['alg'] = 'invalid'
    yield encode_jwt(header, payload, signature)


def header_alg_none(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "none",
          "typ": "JWT"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['alg'] = 'none'
    yield encode_jwt(header, payload, signature)


def header_alg_none_empty_sig(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "none",
          "typ": "JWT"
        }

    We also remove the signature

    Exactly as described in https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['alg'] = 'none'
    signature = ''
    yield encode_jwt(header, payload, signature)


VALID_ALGS = ['HS256',
              'HS384',
              'HS512',
              'RS256',
              'RS384',
              'RS512',
              'ES256',
              'ES384',
              'ES512']


def header_alg_all_possible_values(jwt_string):
    """
    JWT RFC says that these are all the valid values for the alg field:

        HS256	HMAC using SHA-256 hash algorithm
        HS384	HMAC using SHA-384 hash algorithm
        HS512	HMAC using SHA-512 hash algorithm
        RS256	RSA using SHA-256 hash algorithm
        RS384	RSA using SHA-384 hash algorithm
        RS512	RSA using SHA-512 hash algorithm
        ES256	ECDSA using P-256 curve and SHA-256 hash algorithm
        ES384	ECDSA using P-384 curve and SHA-384 hash algorithm
        ES512	ECDSA using P-521 curve and SHA-512 hash algorithm

    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "...",
          "typ": "JWT"
        }

    Where ... will be each of the valid values for the alg field.

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    original_alg = header['alg']
    valid_algs = VALID_ALGS[:]

    # We want to yield different things, if we don't remove the original
    # alg we'll be yielding the exact same JWT
    if original_alg in valid_algs:
        valid_algs.remove(original_alg)

    for alg in valid_algs:
        header['alg'] = alg
        yield encode_jwt(header, payload, signature)
