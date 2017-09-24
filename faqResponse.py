"""
This sample demonstrates an implementation of the Lex Code Hook Interface
in order to serve a sample bot which manages reservations for hotel rooms and car rentals.
Bot, Intent, and Slot models which are compatible with this sample can be found in the Lex Console
as part of the 'BookTrip' template.

For instructions on how to set up and test this bot, as well as additional samples,
visit the Lex Getting Started documentation http://docs.aws.amazon.com/lex/latest/dg/getting-started.html.
"""
import requests
import time
import os
import logging
import json

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


def close(fulfillment, message):
    return {
        'dialogAction': {
            "type": 'Close',
            "fulfillmentState": fulfillment,
            "message": message
        }
    }

# --- Intents ---


def get_answer(intent_request):

    # question = "What is Amazon EC2"
    question = intent_request["inputTranscript"]
    url = "https://westus.api.cognitive.microsoft.com/qnamaker/v2.0/knowledgebases/9958a769-c5bd-42f9-a362-1184c69b8864/generateAnswer"
    payload = "{\n    \"question\":\" "+question+"\"\n}"
    headers = {
        'content-type': "application/json",
        'ocp-apim-subscription-key': "35c4574a8ccf4baa884480d996c33e47",
        'cache-control': "no-cache",
    }

    response = requests.request("POST", url, data=payload, headers=headers)
    answer = json.loads(response.text)['answers'][0]['answer']
    print answer.format()
    return close(
        "Fulfilled",
        {
            "contentType": "PlainText",
            "content": answer.format()
        }
    )


def dispatch(intent_request):
    """
    Called when the user specifies an intent for this bot.
    """

    logger.debug('dispatch userId={}, intentName={}'.format(intent_request['userId'], intent_request['currentIntent']['name']))
    intent_name = intent_request['currentIntent']['name']

    # Dispatch to your bot's intent handlers
    if intent_name == 'AskQuestion':
        return get_answer(intent_request)

    raise Exception('Intent with name ' + intent_name + ' not supported')


# --- Main handler ---


def lambda_handler(event, context):
    """
    Route the incoming request based on intent.
    The JSON body of the request is provided in the event slot.
    """
    # By default, treat the user request as coming from the America/New_York time zone.
    os.environ['TZ'] = 'America/New_York'
    time.tzset()
    logger.debug('event.bot.name={}'.format(event['bot']['name']))
    return dispatch(event)

# event = {
#   "currentIntent": {
#     "name": "AskQuestion"
#   },
#   "bot": {
#     "name": "kea",
#     "alias": "kea",
#     "version": "3"
#   },
#   "userId": "jakir",
#   "inputTranscript": "What is Amazon Lex",
#   "invocationSource": "FulfillmentCodeHook",
#   "outputDialogMode": "Text",
#   "messageVersion": "1.0"
# }

# lambda_handler(event,"hello")