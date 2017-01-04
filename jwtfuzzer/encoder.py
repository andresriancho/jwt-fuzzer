import base64
import json


def base64url_encode(input):
    return base64.urlsafe_b64encode(input).replace(b'=', b'')


def encode_jwt(header, payload, signature):
    """
    Encodes a JWT from its parts.

    This is only used by some parts of the fuzzer which create "valid" JWT. Other parts
    of the fuzzer will output strings.

    :param header: The header as a dict
    :param payload: The payload as a dict
    :param signature: The signature as a string
    :return: A string created from the three inputs.
    """
    header_str = base64url_encode(json.dumps(header,
                                             separators=(',', ':'),))
    payload_str = base64url_encode(json.dumps(payload,
                                              separators=(',', ':'),))
    signature_str = base64url_encode(signature)

    return '.'.join([header_str, payload_str, signature_str])
