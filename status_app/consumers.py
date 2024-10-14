# status_app/consumers.py

import json
from channels.generic.websocket import AsyncWebsocketConsumer
from uuid import UUID


def uuid_to_str(obj):
    if isinstance(obj, UUID):
        return str(obj)
    raise TypeError(f'Object of type {
                    obj.__class__.__name__} is not JSON serializable')


class StatusConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.organization_id = self.scope['url_route']['kwargs']['organization_id']
        self.room_group_name = f'status_{self.organization_id}'

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        # Handle received messages if needed
        pass

    async def status_update(self, event):
        # Send message to WebSocket
        print("here asds")
        await self.send(text_data=json.dumps(event['message'], default=uuid_to_str))
