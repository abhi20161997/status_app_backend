import json
from uuid import UUID
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync


def uuid_to_str(obj):
    if isinstance(obj, UUID):
        return str(obj)
    raise TypeError(f'Object of type {
                    obj.__class__.__name__} is not JSON serializable')


def send_ws_message(organization_id, message_type, data):
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f'status_{organization_id}',
        {
            'type': 'status_update',
            'message': {
                'type': message_type,
                'data': json.loads(json.dumps(data, default=uuid_to_str))
            }
        }
    )
