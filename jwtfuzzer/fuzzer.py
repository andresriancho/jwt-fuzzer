import json

from .fuzzing_functions import (header_alg_empty,
                                header_alg_remove,
                                header_alg_null,
                                header_alg_invalid,
                                header_alg_none)

FUZZING_FUNCTIONS = [header_alg_empty, header_alg_remove, header_alg_null,
                     header_alg_invalid, header_alg_none]


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
        fuzzed_string = fuzzing_function(jwt_string)

        output_data.append(dict(fuzzing_function=fuzzing_function.__name__,
                                jwt=fuzzed_string))

    output = file(output_filename, 'w')
    json.dump(output_data, output, indent=4)

    print('Done!')
