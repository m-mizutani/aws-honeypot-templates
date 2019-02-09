#!/usr/bin/env python

import logging
import json
import dpkt
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    logger.info("%s", json.dumps(event))

    for s3_record in extract_s3_records(event):
        logger.info("s3record = %s", json.dumps(s3_record))


def extract_s3_records(sns_event):
    for sns_record in sns_event.get('Records', []):
        msg = sns_record['Sns']['Message']
        s3event = json.loads(msg)

        for s3_record in s3event['Records']:
            yield s3_record
