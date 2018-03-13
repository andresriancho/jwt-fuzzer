from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt


def payload_remove_aud(jwt_string):
    """
    Removes the aud attribute from the payload (if it exists)

    :param jwt_string: The JWT as a string
    :yield: The different JWT as string
    """
    header, payload, signature = decode_jwt(jwt_string)

    if isinstance(payload, dict):
        if 'aud' in payload:
            del payload['aud']
            yield encode_jwt(header, payload, signature)


def payload_null_aud(jwt_string):
    """
    Sets the aud attribute to null

    :param jwt_string: The JWT as a string
    :yield: The different JWT as string
    """
    header, payload, signature = decode_jwt(jwt_string)

    if isinstance(payload, dict):
        payload['aud'] = None
        yield encode_jwt(header, payload, signature)


def payload_reverse_aud(jwt_string):
    """
    Sets the aud attribute to the reversed string of the original

    :param jwt_string: The JWT as a string
    :yield: The different JWT as string
    """
    header, payload, signature = decode_jwt(jwt_string)

    if isinstance(payload, dict):
        if 'aud' in payload:
            payload['aud'] = payload['aud'][::-1]
            yield encode_jwt(header, payload, signature)


def payload_change_one_letter_aud(jwt_string):
    """
    Sets the aud attribute to a slightly modified version of the original
    Only change the first letter to the letter a.

    :param jwt_string: The JWT as a string
    :yield: The different JWT as string
    """
    header, payload, signature = decode_jwt(jwt_string)

    if isinstance(payload, dict):
        if 'aud' in payload:
            aud = list(payload['aud'])

            if aud[0] != 'a':
                aud[0] = 'a'
            else:
                aud[0] = 'b'

            payload['aud'] = ''.join(aud)
            yield encode_jwt(header, payload, signature)
