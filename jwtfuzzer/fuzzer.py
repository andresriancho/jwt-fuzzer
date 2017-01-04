from .fuzzing_functions import header_alg_empty
FUZZING_FUNCTIONS = [header_alg_empty]


def jwt_fuzzer(jwt_string, output_filename):
    """
    Fuzz JWT and write output to file

    :param jwt_string: The original JWT
    :param output_filename: The output filename
    :return: None
    """
    print('Generating test JSON Web Tokens...')

    output = file(output_filename, 'w')

    for fuzzing_function in FUZZING_FUNCTIONS:
        fuzzed_string = fuzzing_function(jwt_string)
        output.write('%s\n' % fuzzed_string)

    print('Done!')
