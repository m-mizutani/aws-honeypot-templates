#!/usr/bin/env python

import json
import os
import main


def test_main():
    test_data_path = os.getenv("TEST_DATA_PATH") or "test.json"
    jdata = json.load(open(test_data_path, 'rb'))
    res = main.handler(jdata, {})
    print(json.dumps(res, indent=4))
    assert len(res) > 0
