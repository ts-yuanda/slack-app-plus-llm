import os
import json
import logging
import boto3

from msg_handlers.openai_handler import handler_via_assistant as handler
from msg_handlers.action_handler import handle_interactive_message as interactive_handler
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

sqs = boto3.client('sqs')
sqs_url = os.environ['sqs_url']


def lambda_handler(event, context):
    for sqs_msg in event['Records']:
        msg_id = sqs_msg['messageId']
        sqs_receipt_handle = sqs_msg['receiptHandle']

        try:
            # get message attributes
            team_id = sqs_msg['messageAttributes']['team_id']['stringValue']
            event_ts = sqs_msg['messageAttributes']['event_ts']['stringValue']
            channel = sqs_msg['messageAttributes']['channel']['stringValue']
            user = sqs_msg['messageAttributes']['user']['stringValue']
            if team_id == "test_team_id":
                interactive_handler(sqs_msg)
                continue
        except Exception as error:
            logger.error(f"Error at getting message attributes: {str(error)}")

        # Message handling
        try:
            # Get sqs message body (i.e. slack event)
            json_body = sqs_msg["body"]
            body = json.loads(json_body)
            logger.debug(json.dumps(body, indent=2))

            handler(body)
        except Exception as error:
            logger.error(f"Error at event handling: {str(error)}")
            logger.warning(f"Message {msg_id} failed to be processed, here is the full message: {sqs_msg}")

        # Delete message from SQS
        logger.info("Delete from sqs")
        sqs.delete_message(QueueUrl=sqs_url, ReceiptHandle=sqs_receipt_handle)

    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
