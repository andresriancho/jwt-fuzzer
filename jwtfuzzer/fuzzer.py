import json

from .fuzzing_functions import (header_alg_empty,
                                header_alg_remove,
                                header_alg_null,
                                header_alg_invalid,
                                header_alg_none,
                                header_alg_none_empty_sig,
                                header_typ_empty,
                                header_typ_remove,
                                header_typ_null,
                                header_typ_invalid,
                                header_typ_none,
                                header_remove,
                                header_is_a_list,
                                payload_remove,
                                payload_remove_key_value,
                                payload_add_space_to_value,
                                signature_remove,
                                signature_zero,
                                signature_reverse,
                                multiple_dots,
                                all_empty)

FUZZING_FUNCTIONS = [header_alg_empty,
                     header_alg_remove,
                     header_alg_null,
                     header_alg_invalid,
                     header_alg_none,
                     header_alg_none_empty_sig,
                     header_typ_empty,
                     header_typ_remove,
                     header_typ_null,
                     header_typ_invalid,
                     header_typ_none,
                     header_remove,
                     header_is_a_list,
                     payload_remove,
                     payload_remove_key_value,
                     payload_add_space_to_value,
                     signature_remove,
                     signature_zero,
                     signature_reverse,
                     multiple_dots,
                     all_empty]


def jwt_fuzzer(jwt_string, output_filename):
    """
    Fuzz JWT and write output to file

    :param jwt_string: The original JWT
    :param output_filename: The output filename
    :return: None
    """
    print('Generating test JSON Web Tokens...')

    output_data = [dict(fuzzing_function=None, jwt=jwt_string)]

    for fuzzing_function in FUZZING_FUNCTIONS:
        for i, fuzzed_string in enumerate(fuzzing_function(jwt_string)):

            fuzzing_function_id = '%s-%s' % (fuzzing_function.__name__, i)

            output_data.append(dict(fuzzing_function=fuzzing_function_id,
                                    jwt=fuzzed_string))

    output = file(output_filename, 'w')
    json.dump(output_data, output, indent=4)

    print('Done!')
