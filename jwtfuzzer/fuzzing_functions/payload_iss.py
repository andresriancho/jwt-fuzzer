from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt


def payload_remove_iss(jwt_string):
    """
    Removes the iss attribute from the payload (if it exists)

    :param jwt_string: The JWT as a string
    :yield: The different JWT as string
    """
    header, payload, signature = decode_jwt(jwt_string)

    if isinstance(payload, dict):
        if 'iss' in payload:
            del payload['iss']
            yield encode_jwt(header, payload, signature)


def payload_null_iss(jwt_string):
    """
    Sets the iss attribute to null

    :param jwt_string: The JWT as a string
    :yield: The different JWT as string
    """
    header, payload, signature = decode_jwt(jwt_string)

    if isinstance(payload, dict):
        payload['iss'] = None
        yield encode_jwt(header, payload, signature)


def payload_iss_empty(jwt_string):
    """
    Sets the exp attribute to an empty string

    :param jwt_string: The JWT as a string
    :yield: The different JWT as string
    """
    header, payload, signature = decode_jwt(jwt_string)

    if isinstance(payload, dict):
        if 'iss' in payload:
            payload['iss'] = ''
            yield encode_jwt(header, payload, signature)


def payload_iss_change_one_letter(jwt_string):
    """
    Sets the iss attribute to a slightly modified version of the original
    Only change the first letter to the letter a.

    :param jwt_string: The JWT as a string
    :yield: The different JWT as string
    """
    header, payload, signature = decode_jwt(jwt_string)

    if isinstance(payload, dict):
        if 'iss' in payload:
            aud = list(payload['iss'])

            if aud[0] != 'a':
                aud[0] = 'a'
            else:
                aud[0] = 'b'

            payload['iss'] = ''.join(aud)
            yield encode_jwt(header, payload, signature)
