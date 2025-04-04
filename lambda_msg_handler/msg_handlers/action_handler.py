import urllib.parse
import base64
import json
import logging
import os
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from msg_handlers.slack_related.utils import reply

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Slack client
slack_oauth_token = os.environ["slack_oauth_token"]
slack = WebClient(token=slack_oauth_token)

def open_incognito_modal(trigger_id, message_text, channel_id, message_ts):
    """
    Open a modal dialog for the incognito action
    """
    logger.info(f"Opening incognito modal with trigger_id: {trigger_id}")
    logger.info(f"Message text: {message_text}")
    logger.info(f"Channel ID: {channel_id}")
    logger.info(f"Message TS: {message_ts}")
    
    # Create the modal view using Block Kit
    modal_view = {
        "type": "modal",
        "callback_id": "incognito_modal_submission",
        "title": {
            "type": "plain_text",
            "text": "Incognito Message",
            "emoji": True
        },
        "submit": {
            "type": "plain_text",
            "text": "Send",
            "emoji": True
        },
        "close": {
            "type": "plain_text",
            "text": "Cancel",
            "emoji": True
        },
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Original Message:*\n{message_text}"
                }
            },
            {
                "type": "input",
                "block_id": "additional_message",
                "element": {
                    "type": "plain_text_input",
                    "action_id": "additional_message_input",
                    "multiline": True,
                    "placeholder": {
                        "type": "plain_text",
                        "text": "Add your additional message here..."
                    },
                    "min_length": 1,
                    "max_length": 3000
                },
                "label": {
                    "type": "plain_text",
                    "text": "Additional Message",
                    "emoji": True
                },
                "hint": {
                    "type": "plain_text",
                    "text": "Your message will be posted as a thread reply to the original message.",
                    "emoji": True
                }
            }
        ],
        "private_metadata": json.dumps({
            "channel_id": channel_id,
            "message_ts": message_ts
        })
    }
    
    # Log the full modal view for debugging
    logger.info(f"Modal view structure: {json.dumps(modal_view, indent=2)}")
    
    # Call Slack API to open the modal using the SDK
    try:
        # Validate the trigger_id format
        if not trigger_id or len(trigger_id) < 10:
            logger.error(f"Invalid trigger_id format: {trigger_id}")
            return False
            
        # Check if the token is valid
        try:
            auth_test = slack.auth_test()
            logger.info(f"Auth test successful: {auth_test}")
        except SlackApiError as e:
            logger.error(f"Auth test failed: {e.response['error']}")
            return False
            
        # Open the modal
        response = slack.views_open(
            trigger_id=trigger_id,
            view=modal_view
        )
        
        logger.info(f"Modal open response: {response}")
        return True
    except SlackApiError as e:
        error_code = e.response.get('error', 'unknown_error')
        error_message = e.response.get('error', 'Unknown error')
        logger.error(f"Failed to open modal: {error_code} - {error_message}")
        logger.error(f"Full error response: {e.response}")
        
        # Check for specific error types
        if error_code == 'invalid_trigger_id':
            logger.error("The trigger_id is invalid or has expired")
        elif error_code == 'invalid_arguments':
            logger.error("There's an issue with the modal structure")
            
        return False
    except Exception as e:
        logger.error(f"Error opening modal: {e}")
        return False

def handle_modal_submission(payload):
    """
    Handle the submission of the incognito modal
    """
    logger.info("Handling modal submission")
    
    # Extract the submitted values
    view = payload.get("view", {})
    private_metadata = json.loads(view.get("private_metadata", "{}"))
    channel_id = private_metadata.get("channel_id")
    message_ts = private_metadata.get("message_ts")
    
    # Get the additional message from the input
    state = view.get("state", {}).get("values", {})
    additional_message = state.get("additional_message", {}).get("additional_message_input", {}).get("value", "")
    
    logger.info(f"Modal submission - channel: {channel_id}, message_ts: {message_ts}, additional_message: {additional_message}")
    
    # Send a reply to the original message thread using the SDK
    try:
        reply(f"[树洞] {additional_message}", channel_id,
              message_ts, slack)
        return True
    except SlackApiError as e:
        logger.error(f"Failed to post message: {e.response['error']}")
        return False
    except Exception as e:
        logger.error(f"Error posting message: {e}")
        return False


def handle_interactive_message(event):
    logger.info('Processing interactive message')
    body_raw = event.get("body", "")
    
    # The body is base64 encoded, so we need to decode it first
    try:
        decoded_body = base64.b64decode(body_raw).decode('utf-8')
        logger.debug(f"Base64 decoded body: {decoded_body}")
        
        # Now parse the URL-encoded data
        parsed = urllib.parse.parse_qs(decoded_body)
        logger.info(f"Parsed body:\n{parsed}")
    except Exception as e:
        logger.error(f"Failed to decode body: {e}")
        return {"statusCode": 400, "body": "Invalid body format"}

    if "payload" not in parsed:
        logger.warning("Missing 'payload' in parsed body")
        return {"statusCode": 400, "body": "Missing payload"}

    try:
        payload = json.loads(parsed["payload"][0])
        logger.debug("Parsed payload:\n%s", json.dumps(payload, indent=2))
    except Exception as e:
        logger.error(f"Failed to parse payload JSON: {e}")
        return {"statusCode": 400, "body": "Invalid payload"}

    # Check if this is a modal submission
    if payload.get("type") == "view_submission":
        logger.info("Received modal submission")
        success = handle_modal_submission(payload)
        return {
            'statusCode': 200,
            'body': ''
        }

    # Extract key information from the payload
    interactive_type = payload.get('type', 'unknown')
    callback_id = payload.get('callback_id', 'NoCallbackId')
    team_id = payload.get('team', {}).get('id', 'NotFoundInEvent')
    user_id = payload.get('user', {}).get('id', 'NotFoundInEvent')
    channel_id = payload.get('channel', {}).get('id', 'NotFoundInEvent')
    message_ts = payload.get('message_ts', 'NotFoundInEvent')
    trigger_id = payload.get('trigger_id', '')
    response_url = payload.get('response_url', '')
    
    logger.info(f"Interactive message details: type={interactive_type}, callback_id={callback_id}, "
                f"team_id={team_id}, user_id={user_id}, channel_id={channel_id}, message_ts={message_ts}")
    
    # Check if this is our specific shortcut
    if callback_id == 'slack_action_incognito':
        logger.info('Processing incognito shortcut action')
        
        # Extract message text if available
        message_text = ""
        if 'message' in payload and 'text' in payload['message']:
            message_text = payload['message']['text']
            logger.info(f"Message text: {message_text}")
        
        # Open a modal for the user to input additional information
        if trigger_id:
            success = open_incognito_modal(trigger_id, message_text, channel_id, message_ts)
            if success:
                # Return a simple acknowledgment response
                return {
                    'statusCode': 200,
                    'body': ''
                }
            else:
                # If modal opening fails, send a response to the response_url
                try:
                    # Use the SDK to send a response
                    slack.chat_postEphemeral(
                        channel=channel_id,
                        user=user_id,
                        text="Sorry, I couldn't open the modal. Please try again."
                    )
                except Exception as e:
                    logger.error(f"Error sending response: {e}")
                
                return {
                    'statusCode': 500,
                    'body': json.dumps('Failed to open modal')
                }
        else:
            logger.error("No trigger_id found in payload")
            return {
                'statusCode': 400,
                'body': json.dumps('No trigger_id found')
            }
    else:
        logger.info(f'Unhandled callback_id: {callback_id}')
        return {
            'statusCode': 200,
            'body': ''  # Empty body for acknowledgment
        }