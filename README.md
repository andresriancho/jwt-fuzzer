# JSON Web Token Fuzzer

[jwt-fuzzer](https://github.com/andresriancho/jwt-fuzzer) is a simple command line tool that creates
multiple, potentially invalid, strings from an initial [JSON Web Token](https://jwt.io/).

# Installation

```
$ pip install -r requirements.txt
```

# Usage

```
$ ./jwt-fuzzer --jwt={JSON Web Token} --output out.json
Generating test JSON Web Tokens...
Done!
```

Once the output file is generated you'll usually send the modified JWT using the `utils/sender` tool, which
you'll have to customize for your specific case.

