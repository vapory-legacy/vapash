#!/usr/bin/env python3

import argparse
import os


def parse_test(input):
    if not input:
        return ''

    kind = input[0]
    if kind == 0 or kind == 1:
        if len(input) != 41:
            return ''
        header = input[1:33]
        nonce = input[41:32:-1]
        return "k: {}, h: {}, n: {}\n".format(kind, header.hex(), nonce.hex())

    return ''


parser = argparse.ArgumentParser()
parser.add_argument("corpus_dir")
args = parser.parse_args()

print("Corpus dir: {}".format(args.corpus_dir))

output = ''
for test_file_name in os.listdir(args.corpus_dir):
    print("Test: {}".format(test_file_name))
    test_file = os.path.join(args.corpus_dir, test_file_name)
    with open(test_file, 'rb') as f:
        data = f.read()
        output += parse_test(data)

print(output)
