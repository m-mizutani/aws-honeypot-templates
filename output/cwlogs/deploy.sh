#!/bin/bash

REGION=$1
BACKEND_STACK_NAME=$2
OUTPUT_STACK_NAME=$3
CODE_BUCKET=$4
CODE_PREFIX=$5

if [ "$#" -ne 5 ]; then
    echo "syntax) $0 <region> <backend_stack_name> <output_stack_name> <code_s3_bucket> <code_s3_prefix>"
    exit 1
fi

TEMPLATE_FILE="template.yml"
OUTPUT_FILE="sam.yml"

RESOURCES=`aws cloudformation describe-stack-resources --stack-name $BACKEND_STACK_NAME | jq '.["StackResources"][]'`
S3_BUCKET_NAME=`echo $RESOURCES | jq 'select(.LogicalResourceId == "DataStore") | .PhysicalResourceId' -r`
SNS_TOPIC_ARN=`echo $RESOURCES | jq 'select(.LogicalResourceId == "DataStoreNotify") | .PhysicalResourceId' -r`

rm -f src.zip
cd src && pip3 install dpkt --target . && zip -q ../src.zip -r main.py dpkt* -x */__pycache__/* && cd ..

aws cloudformation package \
        --template-file $TEMPLATE_FILE \
        --s3-bucket $CODE_BUCKET \
        --s3-prefix $CODE_PREFIX \
        --output-template-file $OUTPUT_FILE

aws cloudformation deploy \
        --region $REGION \
        --template-file $OUTPUT_FILE \
        --stack-name $OUTPUT_STACK_NAME \
        --parameter-overrides \
        S3BucketName=$S3_BUCKET_NAME \
        SNSTopicArn=$SNS_TOPIC_ARN \
        --capabilities CAPABILITY_IAM
