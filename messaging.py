import os
from twilio.jwt.access_token import AccessToken
from twilio.jwt.access_token.grants import ChatGrant
from twilio.rest import Client
from twilio.base import exceptions
from translations import get_current_locales

sms_service_active = os.environ.get('SMS_ACTIVE', 'False').lower() in ('true', '1')
chat_service_active = os.environ.get('CHAT_ACTIVE', 'False').lower() in ('true', '1')

account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
api_key = os.environ.get('TWILIO_API_KEY')
api_secret = os.environ.get('TWILIO_API_SECRET')
chat_service_sid = os.environ.get('TWILIO_CHAT_SERVICE_SID')
auth_token = os.environ.get('TWILIO_AUTH_TOKEN')
sms_service_sid = os.environ.get('TWILIO_SMS_SERVICE_SID')
sms_sender_id = os.environ.get('SMS_SENDER_ID')

if sms_service_active or chat_service_active:
    client = Client(account_sid, auth_token)


def get_conversation_id(conversation_sid):
    if not chat_service_active:
        return "service is not active"
    try:
        conversation = client.conversations.conversations(conversation_sid).fetch()
        return conversation.unique_name
    except exceptions.TwilioRestException:
        return"conversation does nto exist"


def authenticate_user(identity):
    if not chat_service_active:
        return "service is not active"
    token = AccessToken(account_sid, api_key, api_secret, identity=identity)
    token.add_grant(ChatGrant(service_sid=chat_service_sid))
    return token.to_jwt()


def create_new_conversation_for_action(action_id):
    if not chat_service_active:
        return
    try:
        client.conversations.conversations.create(unique_name=action_id)
    except exceptions.TwilioRestException:
        return "should already exist"


def add_user_to_conversation(action_id, user_uuid):
    if not chat_service_active:
        return
    try:
        client.conversations.conversations(str(action_id)).fetch()
    except exceptions.TwilioRestException:
        create_new_conversation_for_action(action_id)
    finally:
        try:
            conversation = client.conversations.conversations(str(action_id)).fetch()
            conversation.participants.create(identity=user_uuid)
        except exceptions.TwilioRestException:
            return "should be already in"


def send_sms(to_number, msg, code):
    if not isinstance(msg, str):
        msg = msg[get_current_locales()]
    if sms_service_active:
        client.messages.create(to=to_number,
                               from_=sms_sender_id,
                               body=msg + code,
                               messaging_service_sid=sms_service_sid)
