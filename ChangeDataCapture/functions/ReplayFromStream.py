import base64
import os
import json
import boto3

def decode_bytes_if_present(items_by_type):
    # Look for binary values, b64 decode them back into bytes
    for key, value_dict in items_by_type.items():
        for value_type, value in value_dict.items():
            if value_type == "B":
                items_by_type[key] = {value_type: base64.b64decode(value)}

def lambda_handler(event, context):

    # Environment Variables
    target_aws_account_num = os.environ['TARGET_AWS_ACCOUNT_NUMBER']
    target_role_name = os.environ['TARGET_ROLE_NAME']
    target_ddb_name = os.environ['TARGET_DYNAMODB_NAME']
    target_ddb_region = os.environ['TARGET_REGION']

    role_arn = "arn:aws:iam::%s:role/%s" % (target_aws_account_num,target_role_name)

    sts_response = get_credentials(role_arn)
    
    dynamodb = boto3.client('dynamodb', region_name=target_ddb_region,
                            aws_access_key_id = sts_response['AccessKeyId'],
                            aws_secret_access_key = sts_response['SecretAccessKey'],
                            aws_session_token = sts_response['SessionToken'])

    Records = event['Records']
 
    for record in Records:
        event_name = record['eventName']
        
        if event_name == 'REMOVE':
            keys_to_delete = record['dynamodb']['Keys']
            decode_bytes_if_present(keys_to_delete)
            response = dynamodb.delete_item(TableName=target_ddb_name,Key=keys_to_delete)
        else:
            item_to_put = record['dynamodb']['NewImage']
            decode_bytes_if_present(item_to_put)
            response = dynamodb.put_item(TableName=target_ddb_name,Item=item_to_put)
            
def get_credentials(role_arn):
    # create an STS client object that represents a live connection to the 
    # STS service
    sts_client = boto3.client('sts')

    # Call the assume_role method of the STSConnection object and pass the role
    # ARN and a role session name.
    assumed_role_object=sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName="cross_acct_lambda"
    )

    # From the response that contains the assumed role, get the temporary 
    # credentials that can be used to make subsequent API calls
    sts_response=assumed_role_object['Credentials']
    return sts_response
