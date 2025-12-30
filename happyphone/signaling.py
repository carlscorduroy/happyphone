"""Socket.io signaling client for Happy Phone"""

import asyncio
import json
from typing import Callable, Optional, Any
from dataclasses import dataclass

import socketio
from nacl.encoding import Base64Encoder

from .config import SIGNALING_URL
from .crypto import Identity, EncryptedPayload, SealedSenderPayload


@dataclass
class SignalingEvent:
    """Event received from signaling server"""
    type: str
    from_user: Optional[str] = None
    payload: Optional[str] = None
    data: Optional[dict] = None


# Type for event callbacks
EventCallback = Callable[[SignalingEvent], Any]


class SignalingClient:
    """Async Socket.io client for signaling"""

    def __init__(self, url: str = SIGNALING_URL):
        self.url = url
        self.sio = socketio.AsyncClient(
            reconnection=True,
            reconnection_attempts=5,
            reconnection_delay=1,
            reconnection_delay_max=5,
        )
        self.identity: Optional[Identity] = None
        self._listeners: dict[str, list[EventCallback]] = {}
        self._connected = False
        self._registered = False
        self._setup_handlers()

    def _setup_handlers(self):
        """Set up Socket.io event handlers"""

        @self.sio.event
        async def connect():
            self._connected = True
            await self._emit_event('connected', SignalingEvent(type='connected'))
            # Re-register if we have an identity
            if self.identity:
                await self._register()

        @self.sio.event
        async def disconnect():
            self._connected = False
            self._registered = False
            await self._emit_event('disconnected', SignalingEvent(type='disconnected'))

        @self.sio.on('registered')
        async def on_registered(data):
            self._registered = True
            await self._emit_event('registered', SignalingEvent(
                type='registered',
                data=data
            ))

        @self.sio.on('message')
        async def on_message(data):
            await self._emit_event('message', SignalingEvent(
                type='message',
                from_user=data.get('from'),
                payload=data.get('payload'),
                data=data
            ))

        @self.sio.on('call-offer')
        async def on_call_offer(data):
            await self._emit_event('call-offer', SignalingEvent(
                type='call-offer',
                from_user=data.get('from'),
                payload=data.get('payload'),
                data=data
            ))

        @self.sio.on('call-answer')
        async def on_call_answer(data):
            await self._emit_event('call-answer', SignalingEvent(
                type='call-answer',
                from_user=data.get('from'),
                payload=data.get('payload'),
                data=data
            ))

        @self.sio.on('ice-candidate')
        async def on_ice_candidate(data):
            await self._emit_event('ice-candidate', SignalingEvent(
                type='ice-candidate',
                from_user=data.get('from'),
                data=data
            ))

        @self.sio.on('call-end')
        async def on_call_end(data):
            await self._emit_event('call-end', SignalingEvent(
                type='call-end',
                from_user=data.get('from'),
                data=data
            ))

        @self.sio.on('contact-request')
        async def on_contact_request(data):
            await self._emit_event('contact-request', SignalingEvent(
                type='contact-request',
                from_user=data.get('from'),
                payload=data.get('payload'),
                data=data
            ))

        @self.sio.on('contact-response')
        async def on_contact_response(data):
            await self._emit_event('contact-response', SignalingEvent(
                type='contact-response',
                from_user=data.get('from'),
                payload=data.get('payload'),
                data=data
            ))

        @self.sio.on('online-status')
        async def on_online_status(data):
            await self._emit_event('online-status', SignalingEvent(
                type='online-status',
                data=data
            ))

        @self.sio.on('error')
        async def on_error(data):
            await self._emit_event('error', SignalingEvent(
                type='error',
                data=data
            ))

    async def connect(self, identity: Identity):
        """Connect to signaling server"""
        self.identity = identity
        await self.sio.connect(self.url, transports=['websocket'])

    async def _register(self):
        """Register with the signaling server"""
        if not self.identity:
            return

        await self.sio.emit('register', {
            'userId': self.identity.user_id,
            'publicKey': self.identity.public_key_b64(),
            'displayName': self.identity.display_name,
        })

    async def disconnect(self):
        """Disconnect from server"""
        await self.sio.disconnect()
        self._connected = False
        self._registered = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def is_registered(self) -> bool:
        return self._registered

    # === Sending Methods ===

    async def send_message(self, to: str, payload: EncryptedPayload):
        """Send encrypted message (legacy - exposes sender to server)"""
        await self.sio.emit('message', {
            'to': to,
            'payload': json.dumps(payload.to_dict()),
            'type': 'text',
        })

    async def send_sealed_message(self, to: str, payload: SealedSenderPayload):
        """Send sealed sender message (hides sender identity from server)"""
        await self.sio.emit('message', {
            'to': to,
            'payload': json.dumps(payload.to_dict()),
            'type': 'sealed',
        })

    async def send_call_offer(self, to: str, offer: dict, payload: Optional[str] = None):
        """Send WebRTC call offer"""
        await self.sio.emit('call-offer', {
            'to': to,
            'offer': offer,
            'payload': payload,
        })

    async def send_call_answer(self, to: str, answer: dict, payload: Optional[str] = None):
        """Send WebRTC call answer"""
        await self.sio.emit('call-answer', {
            'to': to,
            'answer': answer,
            'payload': payload,
        })

    async def send_ice_candidate(self, to: str, candidate: dict):
        """Send ICE candidate"""
        await self.sio.emit('ice-candidate', {
            'to': to,
            'candidate': candidate,
        })

    async def send_call_end(self, to: str):
        """End a call"""
        await self.sio.emit('call-end', {'to': to})

    async def send_contact_request(self, to: str, challenge: str, payload: str):
        """Send contact verification request"""
        await self.sio.emit('contact-request', {
            'to': to,
            'challenge': challenge,
            'payload': payload,
        })

    async def send_contact_response(self, to: str, response: str, payload: str):
        """Send contact verification response"""
        await self.sio.emit('contact-response', {
            'to': to,
            'response': response,
            'payload': payload,
        })

    async def check_online(self, user_id: str):
        """Check if a user is online"""
        await self.sio.emit('check-online', {'userId': user_id})

    # === Event Listener Management ===

    def on(self, event: str, callback: EventCallback) -> Callable[[], None]:
        """Subscribe to an event. Returns unsubscribe function."""
        if event not in self._listeners:
            self._listeners[event] = []
        self._listeners[event].append(callback)

        def unsubscribe():
            self._listeners[event].remove(callback)
        return unsubscribe

    async def _emit_event(self, event: str, data: SignalingEvent):
        """Emit event to all listeners"""
        if event in self._listeners:
            for callback in self._listeners[event]:
                try:
                    result = callback(data)
                    if asyncio.iscoroutine(result):
                        await result
                except Exception as e:
                    print(f"Error in event handler for {event}: {e}")


# Global signaling client instance
signaling = SignalingClient()
