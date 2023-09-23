#!/usr/bin/python

from .node import parse_from_template


def parser(path=None, file=None):
    if file is None:
        file = open(path, 'rb+')
    return parse_from_template(file)
