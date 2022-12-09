import asyncio
import os
import uuid
from aioapns import APNs, NotificationRequest, PushType
from aioapns.logging import logger
from translations import get_current_locales

loop = asyncio.get_event_loop()
is_apn_configured = True

key_location = os.environ.get('KEY_FILE')
key_id = os.environ.get('KEY_ID')
team_id = os.environ.get('TEAM_ID')
topic = os.environ.get('BUNDLE_ID')
use_sandbox = os.environ.get('APN_SANDBOX', 'False').lower() in ('true', '1')

if not key_id or not key_location or not team_id or not topic:
    is_apn_configured = False


class CustomAPNs(APNs):
    async def send_notification(self, request, error_func=None):
        response = await self.pool.send_notification(request)
        if not response.is_successful:
            if error_func:
                await error_func(request.notification_id,
                                 response, request.device_token)
            logger.error(
                "CustomAPNs: Status of notification %s is %s (%s)",
                request.notification_id,
                response.status,
                response.description,
            )
        return response


async def send_push_notification(root_path, token, msg, collapse_key, error_function):
    apns_key_client = CustomAPNs(
        key=os.path.join(root_path, key_location),
        key_id=key_id,
        team_id=team_id,
        topic=topic,
        use_sandbox=use_sandbox,
    )

    push_request = NotificationRequest(
        device_token=token,
        message={
            "aps": {
                "alert": msg,
                "badge": 1,
                "sound": "default"
            }
        },
        # collapse_key=collapse_key,
        notification_id=str(uuid.uuid4()),
        time_to_live=3,
        push_type=PushType.ALERT,
    )
    await apns_key_client.send_notification(push_request, error_func=error_function)


def send_apple_push(root_path, apns, msg, collapse_key, err_callback):
    if not isinstance(msg, str):
        msg = msg[get_current_locales()]

    for apn in apns:
        loop.run_until_complete(
            send_push_notification(
              root_path,
              apn.token,
              msg,
              collapse_key,
              err_callback))
