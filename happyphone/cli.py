"""Happy Phone CLI - Main Interface"""

import asyncio
import json
import sys
import uuid
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from nacl.encoding import Base64Encoder
import os

from .config import SIGNALING_URL, DATA_DIR, TEE_REQUIRE_ATTESTATION
from .crypto import (
    create_identity, encrypt_message, decrypt_message,
    encrypt_message_ratchet, decrypt_message_ratchet, derive_shared_secret,
    generate_challenge, respond_to_challenge, verify_challenge,
    get_fingerprint, get_shared_fingerprint,
    public_key_to_b64, public_key_from_b64,
    seal_sender, unseal_sender, is_sealed_sender,
    pad_message, unpad_message,
    Identity, Contact, EncryptedPayload, SealedSenderPayload
)
from .session import Session
from .storage import storage, Storage
from .signaling import signaling, SignalingEvent
from .audio import VoiceCall, check_audio_dependencies
from .waveform import WaveformDisplay
from .tee import (
    fetch_attestation, fetch_and_verify_attestation, 
    TEEAttestation, verify_attestation, format_verification_summary
)

# Use plain console without any styling
console = Console(force_terminal=False, no_color=True, legacy_windows=False, markup=False, highlight=False)


class HappyPhoneCLI:
    """Main CLI application"""

    def __init__(self):
        self.identity: Optional[Identity] = None
        self.contacts: dict[str, Contact] = {}  # user_id -> Contact
        self.contacts_by_name: dict[str, Contact] = {}  # lowercase pet_name -> Contact
        self.active_chat: Optional[str] = None  # user_id of active chat
        self.call: Optional[VoiceCall] = None
        self.waveform: Optional[WaveformDisplay] = None
        self.pending_verification: dict = {}  # For keyphrase verification
        self._running = False
        self._message_queue: asyncio.Queue = asyncio.Queue()

    async def start(self):
        """Start the CLI application"""
        console.print(Panel.fit(
            "📱 Happy Phone\n"
            "End-to-End Encrypted Communication"
        ))

        # Initialize storage
        await storage.connect()
        
        # Clean up expired messages
        deleted = await storage.delete_expired_messages()
        if deleted > 0:
            console.print(f"Cleaned up {deleted} expired message(s)")

        # Load or create identity
        self.identity = await storage.get_identity()
        if not self.identity:
            await self._create_identity_flow()

        # Load contacts
        await self._load_contacts()

        # Connect to signaling server
        await self._connect()

        # Set up event handlers
        self._setup_event_handlers()

        # Start main loop
        self._running = True
        await self._main_loop()

    async def _create_identity_flow(self):
        """Interactive first-run identity wizard"""
        session = PromptSession()
        
        # Welcome screen
        console.print("\n" + "═" * 50)
        console.print("  🎉 Welcome to Happy Phone!")
        console.print("═" * 50)
        console.print("\nThis is your first time running Happy Phone.")
        console.print("Let's set up your secure identity in 30 seconds.\n")
        
        # Step 1: Name
        console.print("STEP 1 of 3: Choose your display name")
        console.print("─" * 40)
        console.print("This is what your contacts will see.")
        console.print("Examples: Alice, Bob, Mom, Work Phone\n")
        
        name = ""
        while not name.strip():
            name = await session.prompt_async("Your name: ")
            if not name.strip():
                console.print("Please enter a name.")
        
        # Step 2: Create identity
        console.print("\nSTEP 2 of 3: Generating secure keys...")
        console.print("─" * 40)
        
        self.identity = create_identity(name.strip())
        await storage.save_identity(self.identity)
        
        fingerprint = " ".join(self.identity.get_fingerprint())
        console.print("✓ Cryptographic identity created!\n")
        
        # Step 3: Show ID
        console.print("STEP 3 of 3: Your unique ID")
        console.print("─" * 40)
        console.print(f"\n  ╔══════════════════════════════╗")
        console.print(f"  ║  Your ID:  {self.identity.user_id}            ║")
        console.print(f"  ╚══════════════════════════════╝\n")
        console.print(f"  Fingerprint: {fingerprint}\n")
        
        # Quick start guide
        console.print("═" * 50)
        console.print("  📖 Quick Start Guide")
        console.print("═" * 50)
        console.print("\n1. SHARE your ID with someone you want to chat with")
        console.print(f"   Tell them: \"{self.identity.user_id}\"\n")
        console.print("2. AGREE on a secret keyphrase (e.g., 'pizza')")
        console.print("   Share this in person or via another secure channel\n")
        console.print("3. ADD each other with the same keyphrase:")
        console.print(f"   add <their-id> pizza TheirName\n")
        console.print("4. SEND encrypted messages:")
        console.print("   msg TheirName Hello!\n")
        console.print("Type 'help' anytime to see all commands.\n")
        console.print("═" * 50 + "\n")

    async def _load_contacts(self):
        """Load contacts from storage"""
        contacts = await storage.get_all_contacts()
        self.contacts = {c.user_id: c for c in contacts}
        self.contacts_by_name = {c.pet_name.lower(): c for c in contacts}

    async def _connect(self):
        """Connect to signaling server"""
        console.print(f"Connecting to {SIGNALING_URL}...")
        
        # Check TEE attestation before connecting
        console.print("Verifying server TEE attestation...")
        attestation = await fetch_attestation()
        is_valid, issues = verify_attestation(attestation)
        
        if attestation.is_confidential:
            console.print(f"✓ {attestation.status_line()}")
        else:
            console.print(f"⚠ {attestation.status_line()}")
            if issues:
                for issue in issues:
                    console.print(f"  - {issue}")
            if TEE_REQUIRE_ATTESTATION:
                console.print("✗ TEE attestation required but server is not in TEE.")
                console.print("  Set HAPPYPHONE_TEE_REQUIRED=false to connect anyway.\n")
                return
            console.print("  (Messages are still E2E encrypted)")
        
        try:
            await signaling.connect(self.identity)
            # Wait for registration
            await asyncio.sleep(1)
            if signaling.is_registered:
                console.print("✓ Connected and registered\n")
            else:
                console.print("⚠ Connected but not registered yet\n")
        except Exception as e:
            console.print(f"✗ Connection failed: {e}")
            console.print("You can still view contacts and history offline.\n")

    def _setup_event_handlers(self):
        """Set up signaling event handlers"""

        async def on_message(event: SignalingEvent):
            await self._handle_incoming_message(event)
        signaling.on('message', on_message)

        async def on_contact_request(event: SignalingEvent):
            await self._handle_contact_request(event)
        signaling.on('contact-request', on_contact_request)

        async def on_contact_response(event: SignalingEvent):
            await self._handle_contact_response(event)
        signaling.on('contact-response', on_contact_response)

        async def on_call_offer(event: SignalingEvent):
            await self._handle_call_offer(event)
        signaling.on('call-offer', on_call_offer)

        async def on_call_answer(event: SignalingEvent):
            await self._handle_call_answer(event)
        signaling.on('call-answer', on_call_answer)

        async def on_call_end(event: SignalingEvent):
            await self._handle_call_end(event)
        signaling.on('call-end', on_call_end)

    async def _handle_incoming_message(self, event: SignalingEvent):
        """Handle incoming encrypted message (supports both regular and sealed sender)"""
        if not event.payload:
            return

        try:
            payload_data = json.loads(event.payload)
            
            # Check if this is a sealed sender message
            if is_sealed_sender(payload_data):
                # Sealed sender - extract real sender from encrypted envelope
                sealed_payload = SealedSenderPayload.from_dict(payload_data)
                sender_user_id, sender_public_key, payload, msg_timestamp = unseal_sender(
                    sealed_payload,
                    self.identity.private_key
                )
            else:
                # Legacy format - sender visible to server
                if not event.from_user:
                    return
                sender_user_id = event.from_user
                payload = EncryptedPayload.from_dict(payload_data)
                msg_timestamp = int(datetime.now().timestamp() * 1000)
            
            contact = self.contacts.get(sender_user_id)
            sender_name = contact.pet_name if contact else sender_user_id
            
            # Try Double Ratchet decryption first (v2)
            if payload.version == 2:
                session_state = await storage.get_session_state(sender_user_id)
                if session_state:
                    plaintext, updated_state = decrypt_message_ratchet(payload, session_state)
                    await storage.save_session_state(sender_user_id, updated_state)
                else:
                    # Initialize session if we don't have one (Bob side receiving first message)
                    if contact and contact.public_key:
                        shared_secret = derive_shared_secret(
                            self.identity.private_key,
                            contact.public_key
                        )
                        session = Session.initialize_bob(shared_secret, self.identity.private_key)
                        plaintext, updated_state = decrypt_message_ratchet(
                            payload,
                            session.get_state_dict()
                        )
                        await storage.save_session_state(sender_user_id, updated_state)
                    else:
                        raise ValueError("Cannot decrypt: contact not found or not verified")
            else:
                # Fallback to ephemeral decryption (v1)
                plaintext = decrypt_message(payload, self.identity.private_key)

            # Save message
            msg_id = str(uuid.uuid4())
            await storage.save_message(
                msg_id, sender_user_id, 'received', plaintext, msg_timestamp
            )

            # Display (show 🔒 for sealed sender)
            verified = "✓" if contact and contact.verified else "⚠"
            sealed_icon = "🔒" if is_sealed_sender(payload_data) else ""
            console.print(f"\n[{sender_name}] {verified}{sealed_icon}: {plaintext}")

        except Exception as e:
            sender_name = event.from_user or "unknown"
            console.print(f"\nFailed to decrypt message from {sender_name}: {e}")

    async def _handle_contact_request(self, event: SignalingEvent):
        """Handle incoming contact verification request"""
        if not event.from_user or not event.data:
            return

        challenge = event.data.get('challenge')
        payload_str = event.data.get('payload')

        if not challenge or not payload_str:
            return

        try:
            payload = json.loads(payload_str)
            salt = payload.get('salt')
            their_public_key = payload.get('publicKey')

            if not salt or not their_public_key:
                return

            # Store for when user provides keyphrase
            self.pending_verification[event.from_user] = {
                'challenge': challenge,
                'salt': salt,
                'public_key': their_public_key,
                'direction': 'incoming',
            }

            console.print(f"\n📨 Contact request from {event.from_user}")
            console.print(f"Use: add {event.from_user} <keyphrase> <name>")

        except Exception as e:
            console.print(f"\nFailed to parse contact request: {e}")

    async def _handle_contact_response(self, event: SignalingEvent):
        """Handle contact verification response"""
        if not event.from_user or not event.payload:
            return

        pending = self.pending_verification.get(event.from_user)
        if not pending or pending.get('direction') != 'outgoing':
            return

        try:
            data = json.loads(event.payload)
            response = data.get('response')
            their_public_key = data.get('publicKey')

            if not response or not their_public_key:
                return

            # Verify the response
            challenge_bytes = Base64Encoder.decode(pending['challenge'].encode())
            salt_bytes = Base64Encoder.decode(pending['salt'].encode())
            response_bytes = Base64Encoder.decode(response.encode())

            if verify_challenge(challenge_bytes, salt_bytes, response_bytes, pending['keyphrase']):
                # Success! Add contact
                contact = Contact(
                    user_id=event.from_user,
                    public_key=public_key_from_b64(their_public_key),
                    display_name=pending.get('pet_name', event.from_user),
                    pet_name=pending.get('pet_name', event.from_user),
                    trust_tier=pending.get('trust_tier', 'other'),
                    verified=True,
                )
                await storage.save_contact(contact)
                self.contacts[contact.user_id] = contact
                self.contacts_by_name[contact.pet_name.lower()] = contact

                # Initialize Double Ratchet session (Alice side - sender)
                shared_secret = derive_shared_secret(
                    self.identity.private_key,
                    contact.public_key
                )
                session = Session.initialize_alice(shared_secret, contact.public_key)
                await storage.save_session_state(event.from_user, session.get_state_dict())

                console.print(f"\n✓ Contact verified and added: {contact.pet_name}")
            else:
                console.print(f"\n✗ Verification failed - keyphrase mismatch")

            del self.pending_verification[event.from_user]

        except Exception as e:
            console.print(f"\nFailed to process contact response: {e}")

    async def _handle_call_offer(self, event: SignalingEvent):
        """Handle incoming call"""
        if not event.from_user:
            return

        contact = self.contacts.get(event.from_user)
        caller_name = contact.pet_name if contact else event.from_user
        verified = "✓" if contact and contact.verified else "⚠"

        console.print(f"\n📞 Incoming call from {caller_name} {verified}")
        console.print("Type 'answer' to accept or 'decline' to reject")

        # Store offer for answering
        self.pending_verification[f"call_{event.from_user}"] = event.data.get('offer')

    async def _handle_call_answer(self, event: SignalingEvent):
        """Handle call answer"""
        if not self.call or not event.data:
            return

        try:
            await self.call.handle_answer(event.data.get('answer', {}))
            console.print("📞 Call connected!")
            # Start waveform animation
            self.waveform = WaveformDisplay(console=console)
            await self.waveform.start()
        except Exception as e:
            console.print(f"Call connection failed: {e}")

    async def _handle_call_end(self, event: SignalingEvent):
        """Handle call end"""
        if self.waveform:
            await self.waveform.stop()
            self.waveform = None
        if self.call and self.call.is_active:
            await self.call.hangup()
            console.print("\n📞 Call ended by remote party")
        self.call = None

    async def _main_loop(self):
        """Main input loop"""
        session = PromptSession()

        self._print_help()

        with patch_stdout():
            while self._running:
                try:
                    prompt_text = f"[{self.identity.user_id}]> "
                    user_input = await session.prompt_async(prompt_text)

                    if user_input.strip():
                        await self._handle_command(user_input.strip())

                except KeyboardInterrupt:
                    break
                except EOFError:
                    break
                except Exception as e:
                    console.print(f"Error: {e}")

        # Cleanup
        await self._shutdown()

    async def _handle_command(self, input_text: str):
        """Handle user command"""
        parts = input_text.split(maxsplit=3)
        cmd = parts[0].lower()

        if cmd == 'help':
            self._print_help()

        elif cmd == 'status':
            await self._cmd_status()

        elif cmd == 'id':
            self._cmd_id()

        elif cmd == 'contacts':
            await self._cmd_contacts()

        elif cmd == 'add':
            if len(parts) < 3:
                console.print("Usage: add <user_id> <keyphrase> [name] [tier]")
            else:
                user_id = parts[1]
                keyphrase = parts[2]
                name = parts[3] if len(parts) > 3 else user_id
                await self._cmd_add_contact(user_id, keyphrase, name)

        elif cmd == 'msg':
            if len(parts) < 3:
                console.print("Usage: msg <name> <message>")
            else:
                name = parts[1]
                message = input_text.split(maxsplit=2)[2]
                await self._cmd_send_message(name, message)

        elif cmd == 'chat':
            if len(parts) < 2:
                console.print("Usage: chat <name>")
            else:
                await self._cmd_chat(parts[1])

        elif cmd == 'history':
            name = parts[1] if len(parts) > 1 else None
            await self._cmd_history(name)

        elif cmd == 'call':
            if len(parts) < 2:
                console.print("Usage: call <name>")
            else:
                await self._cmd_call(parts[1])

        elif cmd == 'answer':
            await self._cmd_answer()

        elif cmd == 'decline':
            await self._cmd_decline()

        elif cmd == 'hangup':
            await self._cmd_hangup()

        elif cmd == 'delete':
            if len(parts) < 2:
                console.print("Usage: delete <name>")
            else:
                await self._cmd_delete_contact(parts[1])

        elif cmd == 'reset':
            await self._cmd_reset()

        elif cmd == 'tee':
            # Check for 'tee verify' subcommand
            if len(parts) > 1 and parts[1].lower() == 'verify':
                await self._cmd_tee(detailed=True)
            else:
                await self._cmd_tee()

        elif cmd in ('quit', 'exit', 'q'):
            self._running = False

        else:
            console.print(f"Unknown command: {cmd}. Type 'help' for commands.")

    def _print_help(self):
        """Print help message"""
        help_text = """
Commands:
  status                     Show connection status
  id                         Show your user ID and fingerprint
  contacts                   List all contacts
  add <id> <phrase> [name]   Add contact with keyphrase verification
  msg <name> <text>          Send encrypted message
  chat <name>                Start chat session (continuous messaging)
  history [name]             Show message history
  call <name>                Start voice call
  answer                     Answer incoming call
  decline                    Decline incoming call
  hangup                     End current call
  tee                        Show server TEE attestation status
  tee verify                  Cryptographically verify TEE attestation
  delete <name>              Delete a contact
  reset                      Delete identity and all data
  quit                       Exit
"""
        console.print(help_text)

    async def _cmd_status(self):
        """Show status"""
        status = "Connected" if signaling.is_connected else "Disconnected"
        registered = "Yes" if signaling.is_registered else "No"

        audio_ok, missing = check_audio_dependencies()
        audio_status = "Available" if audio_ok else f"Missing: {', '.join(missing)}"

        # Fetch TEE status
        attestation = await fetch_attestation()
        tee_status = attestation.status_line()

        console.print(f"\n  Server: {status}")
        console.print(f"  Registered: {registered}")
        console.print(f"  {tee_status}")
        console.print(f"  Audio: {audio_status}")
        console.print(f"  Contacts: {len(self.contacts)}")
        console.print(f"  Data dir: {DATA_DIR}\n")

    async def _cmd_tee(self, detailed: bool = False):
        """Show TEE attestation status"""
        if detailed:
            console.print("\nFetching TEE attestation with cryptographic verification...")
            console.print("This verifies the AMD certificate chain and report signature.\n")
            
            attestation = await fetch_and_verify_attestation()
            
            # Print detailed verification summary
            summary = format_verification_summary(attestation)
            for line in summary.split('\n'):
                console.print(f"  {line}")
        else:
            console.print("\nFetching TEE attestation from server...")
            
            attestation = await fetch_attestation()
            
            console.print(f"\n  {attestation.status_line()}")
            
            if attestation.is_confidential:
                console.print(f"  VM ID: {attestation.vm_id or 'N/A'}")
                console.print(f"  Location: {attestation.location or 'N/A'}")
                console.print(f"  Server Version: {attestation.server_version or 'N/A'}")
                console.print(f"\n  Use 'tee verify' for cryptographic verification.")
            elif attestation.error:
                console.print(f"  Could not verify server attestation.")
            else:
                console.print(f"  Warning: Server is not running in a TEE.")
                console.print(f"  Messages are still E2E encrypted, but server")
                console.print(f"  memory could theoretically be inspected.")
        console.print()

    def _cmd_id(self):
        """Show identity"""
        fingerprint = " ".join(self.identity.get_fingerprint())
        console.print(f"\n  User ID: {self.identity.user_id}")
        console.print(f"  Name: {self.identity.display_name}")
        console.print(f"  Fingerprint: {fingerprint}")
        console.print(f"\n  Share your User ID with contacts\n")

    async def _cmd_contacts(self):
        """List contacts"""
        if not self.contacts:
            console.print("\nNo contacts yet. Use 'add' to add someone.\n")
            return

        table = Table(title="Contacts")
        table.add_column("Name", style="cyan")
        table.add_column("ID", style="dim")
        table.add_column("Verified", style="green")
        table.add_column("Tier")

        for contact in self.contacts.values():
            verified = "✓" if contact.verified else "⚠"
            table.add_row(
                contact.pet_name,
                contact.user_id,
                verified,
                contact.trust_tier
            )

        console.print(table)

    async def _cmd_add_contact(self, user_id: str, keyphrase: str, pet_name: str):
        """Add a new contact with keyphrase verification"""
        if not signaling.is_connected:
            console.print("Not connected to server")
            return

        # Check if already exists
        if user_id in self.contacts:
            console.print(f"Contact {user_id} already exists")
            return

        # Check if there's a pending incoming request
        pending = self.pending_verification.get(user_id)
        if pending and pending.get('direction') == 'incoming':
            # Respond to their request
            try:
                challenge_bytes = Base64Encoder.decode(pending['challenge'].encode())
                salt_bytes = Base64Encoder.decode(pending['salt'].encode())

                response = respond_to_challenge(challenge_bytes, salt_bytes, keyphrase)
                response_b64 = Base64Encoder.encode(response).decode()

                await signaling.send_contact_response(
                    user_id,
                    response_b64,
                    json.dumps({
                        'response': response_b64,
                        'publicKey': self.identity.public_key_b64(),
                    })
                )

                # Add contact
                contact = Contact(
                    user_id=user_id,
                    public_key=public_key_from_b64(pending['public_key']),
                    display_name=pet_name,
                    pet_name=pet_name,
                    trust_tier='other',
                    verified=True,
                )
                await storage.save_contact(contact)
                self.contacts[contact.user_id] = contact
                self.contacts_by_name[contact.pet_name.lower()] = contact

                # Initialize Double Ratchet session (Bob side - receiver)
                shared_secret = derive_shared_secret(
                    self.identity.private_key,
                    contact.public_key
                )
                session = Session.initialize_bob(shared_secret, self.identity.private_key)
                await storage.save_session_state(user_id, session.get_state_dict())

                console.print(f"✓ Contact added: {pet_name}")
                del self.pending_verification[user_id]
                return

            except Exception as e:
                console.print(f"Failed to respond: {e}")
                return

        # Initiate new request
        console.print(f"Sending verification request to {user_id}...")

        try:
            challenge, salt = generate_challenge()
            challenge_b64 = Base64Encoder.encode(challenge).decode()
            salt_b64 = Base64Encoder.encode(salt).decode()

            await signaling.send_contact_request(
                user_id,
                challenge_b64,
                json.dumps({
                    'salt': salt_b64,
                    'publicKey': self.identity.public_key_b64(),
                })
            )

            # Store pending verification
            self.pending_verification[user_id] = {
                'challenge': challenge_b64,
                'salt': salt_b64,
                'keyphrase': keyphrase,
                'pet_name': pet_name,
                'trust_tier': 'other',
                'direction': 'outgoing',
            }

            # Add contact immediately (will be marked verified when they respond)
            contact = Contact(
                user_id=user_id,
                public_key=None,  # Will be set when they respond
                display_name=pet_name,
                pet_name=pet_name,
                trust_tier='other',
                verified=False,  # Not verified until they respond
            )
            await storage.save_contact(contact)
            self.contacts[contact.user_id] = contact
            self.contacts_by_name[contact.pet_name.lower()] = contact

            console.print(f"✓ Contact added: {pet_name} (unverified)")
            console.print(f"Waiting for {user_id} to verify...")
            console.print(f"They need to run: add {self.identity.user_id} {keyphrase} <your_name>")

        except Exception as e:
            console.print(f"Failed to send request: {e}")

    async def _cmd_send_message(self, name: str, message: str):
        """Send encrypted message"""
        contact = self.contacts_by_name.get(name.lower())
        if not contact:
            contact = self.contacts.get(name)  # Try user_id

        if not contact:
            console.print(f"Contact '{name}' not found")
            return

        if not contact.verified or not contact.public_key:
            console.print(f"Contact '{name}' is not verified yet. Wait for them to complete verification.")
            return

        if not signaling.is_connected:
            console.print("Not connected to server")
            return

        try:
            # Try to get session state for Double Ratchet
            session_state = await storage.get_session_state(contact.user_id)
            
            # Check if session is ready to send (has sending_chain_key)
            if session_state and session_state.get('sending_chain_key'):
                # Use Double Ratchet
                inner_payload, updated_state = encrypt_message_ratchet(message, session_state)
                await storage.save_session_state(contact.user_id, updated_state)
            else:
                # Fallback to ephemeral encryption (no session or session not ready)
                inner_payload = encrypt_message(message, contact.public_key)

            # Wrap in sealed sender to hide our identity from the server
            timestamp = int(datetime.now().timestamp() * 1000)
            sealed_payload = seal_sender(
                inner_payload,
                self.identity,
                contact.public_key,
                timestamp
            )

            # Send (server only sees recipient, not sender)
            await signaling.send_sealed_message(contact.user_id, sealed_payload)

            # Save locally
            msg_id = str(uuid.uuid4())
            timestamp = int(datetime.now().timestamp() * 1000)
            await storage.save_message(msg_id, contact.user_id, 'sent', message, timestamp)

            console.print(f"→ {contact.pet_name}: {message}")

        except Exception as e:
            console.print(f"Failed to send: {e}")

    async def _cmd_chat(self, name: str):
        """Start chat session with continuous messaging"""
        contact = self.contacts_by_name.get(name.lower())
        if not contact:
            contact = self.contacts.get(name)

        if not contact:
            console.print(f"Contact '{name}' not found")
            return

        if not signaling.is_connected:
            console.print("Not connected to server")
            return

        console.print(f"\n=== Chat with {contact.pet_name} ===")
        console.print("Type your messages below. Type '/exit' to leave chat, '/history' to see history.\n")

        session = PromptSession()
        
        # Use patch_stdout to allow incoming messages to display cleanly while typing
        with patch_stdout():
            while True:
                try:
                    user_input = await session.prompt_async(f"{contact.pet_name}> ")
                    
                    if not user_input.strip():
                        continue
                    
                    if user_input.strip() == '/exit':
                        console.print("\nExited chat mode.\n")
                        break
                    
                    if user_input.strip() == '/history':
                        messages = await storage.get_messages(contact.user_id, limit=10)
                        if messages:
                            console.print("\nRecent messages:")
                            for msg in messages:
                                direction = "→" if msg['direction'] == 'sent' else "←"
                                time_str = datetime.fromtimestamp(msg['timestamp'] / 1000).strftime('%H:%M')
                                console.print(f"  {time_str} {direction} {msg['content']}")
                            console.print()
                        else:
                            console.print("No message history\n")
                        continue
                    
                    # Send the message
                    await self._cmd_send_message(contact.pet_name, user_input.strip())
                    
                except KeyboardInterrupt:
                    console.print("\nExited chat mode.\n")
                    break
                except EOFError:
                    console.print("\nExited chat mode.\n")
                    break
                except Exception as e:
                    console.print(f"Error: {e}")

    async def _cmd_history(self, name: Optional[str]):
        """Show message history"""
        if name:
            contact = self.contacts_by_name.get(name.lower())
            if not contact:
                contact = self.contacts.get(name)
            if not contact:
                console.print(f"Contact '{name}' not found")
                return

            messages = await storage.get_messages(contact.user_id, limit=20)
            if not messages:
                console.print(f"No messages with {contact.pet_name}")
                return

            console.print(f"\nMessages with {contact.pet_name}\n")
            for msg in messages:
                direction = "→" if msg['direction'] == 'sent' else "←"
                time_str = datetime.fromtimestamp(msg['timestamp'] / 1000).strftime('%H:%M')
                console.print(f"  {time_str} {direction} {msg['content']}")
            console.print()
        else:
            console.print("Usage: history <name>")

    async def _cmd_call(self, name: str):
        """Start voice call"""
        contact = self.contacts_by_name.get(name.lower())
        if not contact:
            console.print(f"Contact '{name}' not found")
            return

        audio_ok, missing = check_audio_dependencies()
        if not audio_ok:
            console.print(f"Audio not available. Missing: {', '.join(missing)}")
            console.print("Install with: pip install pyaudio aiortc")
            return

        if not signaling.is_connected:
            console.print("Not connected to server")
            return

        try:
            self.call = VoiceCall()
            await self.call.create_peer_connection(contact.user_id)
            await self.call.add_microphone()

            offer = await self.call.create_offer()
            await signaling.send_call_offer(contact.user_id, offer)

            console.print(f"📞 Calling {contact.pet_name}...")

        except Exception as e:
            console.print(f"Failed to start call: {e}")
            self.call = None

    async def _cmd_answer(self):
        """Answer incoming call"""
        # Check audio dependencies first
        audio_ok, missing = check_audio_dependencies()
        if not audio_ok:
            console.print(f"Audio not available. Missing: {', '.join(missing)}")
            console.print("Install with: pip install pyaudio aiortc")
            return

        # Find pending call
        call_key = None
        offer = None
        for key in list(self.pending_verification.keys()):
            if key.startswith('call_'):
                call_key = key
                offer = self.pending_verification[key]
                break

        if not offer:
            console.print("No incoming call to answer")
            return

        user_id = call_key.replace('call_', '')

        try:
            self.call = VoiceCall()
            await self.call.create_peer_connection(user_id)
            await self.call.add_microphone()

            answer = await self.call.handle_offer(offer)
            await signaling.send_call_answer(user_id, answer)

            del self.pending_verification[call_key]
            console.print("📞 Call connected!")
            # Start waveform animation
            self.waveform = WaveformDisplay(console=console)
            await self.waveform.start()

        except Exception as e:
            console.print(f"Failed to answer: {e}")
            self.call = None

    async def _cmd_decline(self):
        """Decline incoming call"""
        call_key = None
        for key in list(self.pending_verification.keys()):
            if key.startswith('call_'):
                call_key = key
                break

        if call_key:
            user_id = call_key.replace('call_', '')
            await signaling.send_call_end(user_id)
            del self.pending_verification[call_key]
            console.print("Call declined")
        else:
            console.print("No incoming call to decline")

    async def _cmd_hangup(self):
        """End current call"""
        if self.call and self.call.is_active:
            if self.waveform:
                await self.waveform.stop()
                self.waveform = None
            await signaling.send_call_end(self.call.remote_user_id)
            await self.call.hangup()
            self.call = None
            console.print("📞 Call ended")
        else:
            console.print("No active call")

    async def _cmd_delete_contact(self, name: str):
        """Delete a contact"""
        contact = self.contacts_by_name.get(name.lower())
        if not contact:
            console.print(f"Contact '{name}' not found")
            return

        await storage.delete_contact(contact.user_id)
        del self.contacts[contact.user_id]
        del self.contacts_by_name[contact.pet_name.lower()]
        console.print(f"✓ Contact '{contact.pet_name}' deleted")

    async def _cmd_reset(self):
        """Reset all data"""
        console.print("This will delete your identity and all contacts!")
        session = PromptSession()
        confirm = await session.prompt_async("Type 'yes' to confirm: ")

        if confirm.lower() == 'yes':
            await storage.delete_identity()
            console.print("✓ All data deleted. Restart the app to create a new identity.")
            self._running = False
        else:
            console.print("Cancelled")

    async def _shutdown(self):
        """Clean shutdown"""
        console.print("\nShutting down...")

        if self.waveform:
            await self.waveform.stop()
            self.waveform = None

        if self.call and self.call.is_active:
            await self.call.hangup()

        await signaling.disconnect()
        await storage.close()

        console.print("Goodbye! 👋")


def main():
    """Entry point"""
    cli = HappyPhoneCLI()
    try:
        asyncio.run(cli.start())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
