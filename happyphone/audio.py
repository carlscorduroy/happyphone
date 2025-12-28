"""Audio handling for voice calls using WebRTC"""

import asyncio
import fractions
from typing import Optional, Callable
import time

try:
    import pyaudio
    PYAUDIO_AVAILABLE = True
except (ImportError, OSError):
    PYAUDIO_AVAILABLE = False

try:
    import sounddevice as sd
    SOUNDDEVICE_AVAILABLE = True
except ImportError:
    SOUNDDEVICE_AVAILABLE = False

# Prefer pyaudio if available, otherwise use sounddevice
AUDIO_BACKEND = 'pyaudio' if PYAUDIO_AVAILABLE else ('sounddevice' if SOUNDDEVICE_AVAILABLE else None)

try:
    from aiortc import (
        RTCPeerConnection,
        RTCSessionDescription,
        RTCConfiguration,
        RTCIceServer,
        MediaStreamTrack,
    )
    from aiortc.contrib.media import MediaPlayer, MediaRecorder, MediaBlackhole
    from av import AudioFrame
    import numpy as np
    AIORTC_AVAILABLE = True
except ImportError:
    AIORTC_AVAILABLE = False
    # Dummy classes for type hints
    MediaStreamTrack = object
    AudioFrame = object

from .config import (
    TURN_SERVER, TURN_USERNAME, TURN_PASSWORD, STUN_SERVER,
    AUDIO_SAMPLE_RATE, AUDIO_CHANNELS, AUDIO_CHUNK_SIZE
)


if AIORTC_AVAILABLE and PYAUDIO_AVAILABLE:
    class MicrophoneTrack(MediaStreamTrack):
        """Audio track that captures from microphone"""

        kind = "audio"

        def __init__(self):
            super().__init__()
            self._pa = pyaudio.PyAudio()
            self._stream = self._pa.open(
                format=pyaudio.paInt16,
                channels=AUDIO_CHANNELS,
                rate=AUDIO_SAMPLE_RATE,
                input=True,
                frames_per_buffer=AUDIO_CHUNK_SIZE,
            )
            self._start_time = time.time()
            self._frame_count = 0

        async def recv(self):
            """Receive next audio frame from microphone"""
            # Read audio data
            data = self._stream.read(AUDIO_CHUNK_SIZE, exception_on_overflow=False)

            # Convert to numpy array
            audio_array = np.frombuffer(data, dtype=np.int16)

            # Create AudioFrame
            frame = AudioFrame(format='s16', layout='mono', samples=AUDIO_CHUNK_SIZE)
            frame.sample_rate = AUDIO_SAMPLE_RATE
            frame.pts = self._frame_count * AUDIO_CHUNK_SIZE
            frame.time_base = fractions.Fraction(1, AUDIO_SAMPLE_RATE)

            # Copy data to frame
            frame.planes[0].update(audio_array.tobytes())

            self._frame_count += 1

            # Add small delay to maintain timing
            elapsed = time.time() - self._start_time
            expected = self._frame_count * AUDIO_CHUNK_SIZE / AUDIO_SAMPLE_RATE
            if expected > elapsed:
                await asyncio.sleep(expected - elapsed)

            return frame

        def stop(self):
            """Stop the microphone track"""
            super().stop()
            if self._stream:
                self._stream.stop_stream()
                self._stream.close()
            if self._pa:
                self._pa.terminate()


if PYAUDIO_AVAILABLE:
    class AudioPlayer:
        """Play received audio through speakers"""

        def __init__(self):
            self._pa = pyaudio.PyAudio()
            self._stream = self._pa.open(
                format=pyaudio.paInt16,
                channels=AUDIO_CHANNELS,
                rate=AUDIO_SAMPLE_RATE,
                output=True,
                frames_per_buffer=AUDIO_CHUNK_SIZE,
            )

        def play(self, frame):
            """Play an audio frame"""
            # Convert frame to bytes and play
            data = bytes(frame.planes[0])
            self._stream.write(data)

        def close(self):
            """Close the audio player"""
            if self._stream:
                self._stream.stop_stream()
                self._stream.close()
            if self._pa:
                self._pa.terminate()


if AIORTC_AVAILABLE:
    class VoiceCall:
        """WebRTC voice call manager"""

        def __init__(self):
            self.pc: Optional[RTCPeerConnection] = None
            self.mic_track = None
            self.audio_player = None
            self.remote_user_id: Optional[str] = None
            self._state = 'idle'
            self._on_state_change: Optional[Callable[[str], None]] = None
            self._playback_task: Optional[asyncio.Task] = None

        @property
        def state(self) -> str:
            return self._state

        def _set_state(self, state: str):
            self._state = state
            if self._on_state_change:
                self._on_state_change(state)

        def on_state_change(self, callback: Callable[[str], None]):
            """Set callback for state changes"""
            self._on_state_change = callback

        async def create_peer_connection(self, remote_user_id: str):
            """Create and configure peer connection"""
            if not AIORTC_AVAILABLE:
                raise RuntimeError("aiortc not installed. Run: pip install aiortc")

            self.remote_user_id = remote_user_id

            # Configure ICE servers
            ice_servers = [
                RTCIceServer(urls=["stun:stun.l.google.com:19302"]),
                RTCIceServer(urls=[STUN_SERVER]),
            ]

            # Add TURN if configured
            if TURN_PASSWORD:
                ice_servers.append(RTCIceServer(
                    urls=[TURN_SERVER],
                    username=TURN_USERNAME,
                    credential=TURN_PASSWORD,
                ))

            config = RTCConfiguration(iceServers=ice_servers)
            self.pc = RTCPeerConnection(configuration=config)

            # Handle incoming tracks
            @self.pc.on("track")
            async def on_track(track):
                if track.kind == "audio":
                    print("📥 Receiving remote audio")
                    self._playback_task = asyncio.create_task(self._play_remote_audio(track))

            # Handle connection state changes
            @self.pc.on("connectionstatechange")
            async def on_connection_state_change():
                state = self.pc.connectionState
                print(f"📞 Connection state: {state}")
                if state == "connected":
                    self._set_state('connected')
                elif state == "failed":
                    self._set_state('failed')
                elif state == "closed":
                    self._set_state('ended')

            @self.pc.on("iceconnectionstatechange")
            async def on_ice_state_change():
                print(f"🧊 ICE state: {self.pc.iceConnectionState}")

            return self.pc

        async def _play_remote_audio(self, track):
            """Play audio from remote track"""
            if not PYAUDIO_AVAILABLE:
                print("⚠️ pyaudio not available, cannot play audio")
                return

            self.audio_player = AudioPlayer()
            try:
                while True:
                    frame = await track.recv()
                    self.audio_player.play(frame)
            except Exception as e:
                if "MediaStreamError" not in str(type(e).__name__):
                    print(f"Audio playback error: {e}")
            finally:
                if self.audio_player:
                    self.audio_player.close()
                    self.audio_player = None

        async def add_microphone(self):
            """Add microphone track to peer connection"""
            if not PYAUDIO_AVAILABLE:
                print("⚠️ pyaudio not available, microphone disabled")
                return

            if not self.pc:
                raise RuntimeError("No peer connection")

            self.mic_track = MicrophoneTrack()
            self.pc.addTrack(self.mic_track)
            print("🎤 Microphone added")

        async def create_offer(self) -> dict:
            """Create SDP offer (caller side)"""
            if not self.pc:
                raise RuntimeError("No peer connection")

            self._set_state('calling')
            offer = await self.pc.createOffer()
            await self.pc.setLocalDescription(offer)

            return {
                "type": offer.type,
                "sdp": offer.sdp,
            }

        async def handle_offer(self, offer: dict) -> dict:
            """Handle incoming offer and create answer (callee side)"""
            if not self.pc:
                raise RuntimeError("No peer connection")

            self._set_state('ringing')

            desc = RTCSessionDescription(sdp=offer["sdp"], type=offer["type"])
            await self.pc.setRemoteDescription(desc)

            answer = await self.pc.createAnswer()
            await self.pc.setLocalDescription(answer)

            return {
                "type": answer.type,
                "sdp": answer.sdp,
            }

        async def handle_answer(self, answer: dict):
            """Handle incoming answer (caller side)"""
            if not self.pc:
                raise RuntimeError("No peer connection")

            desc = RTCSessionDescription(sdp=answer["sdp"], type=answer["type"])
            await self.pc.setRemoteDescription(desc)

        async def add_ice_candidate(self, candidate: dict):
            """Add ICE candidate from remote peer"""
            if not self.pc:
                return

            # aiortc handles ICE candidates internally through the SDP
            # This is a placeholder for explicit candidate handling if needed
            pass

        async def hangup(self):
            """End the call"""
            self._set_state('ended')

            if self._playback_task:
                self._playback_task.cancel()
                self._playback_task = None

            if self.mic_track:
                self.mic_track.stop()
                self.mic_track = None

            if self.audio_player:
                self.audio_player.close()
                self.audio_player = None

            if self.pc:
                await self.pc.close()
                self.pc = None

            self.remote_user_id = None
            print("📞 Call ended")

        @property
        def is_active(self) -> bool:
            return self._state in ('calling', 'ringing', 'connected')
else:
    # Stub when aiortc not available
    class VoiceCall:
        def __init__(self):
            self.is_active = False


# Check dependencies on import
def check_audio_dependencies() -> tuple[bool, list[str]]:
    """Check if audio dependencies are available"""
    missing = []
    if not PYAUDIO_AVAILABLE:
        missing.append("pyaudio")
    if not AIORTC_AVAILABLE:
        missing.append("aiortc")
    return len(missing) == 0, missing
