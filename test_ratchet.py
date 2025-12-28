#!/usr/bin/env python3
"""Test Double Ratchet implementation"""

import asyncio
from happyphone.crypto import create_identity, derive_shared_secret, encrypt_message_ratchet, decrypt_message_ratchet
from happyphone.session import Session


async def test_basic_exchange():
    """Test basic message exchange with Double Ratchet"""
    print("=== Testing Double Ratchet Basic Exchange ===\n")
    
    # Create Alice and Bob identities
    alice = create_identity("Alice")
    bob = create_identity("Bob")
    
    # Derive shared secret (DH between identity keys)
    shared_secret = derive_shared_secret(alice.private_key, bob.public_key)
    
    # Initialize sessions
    print("1. Initializing sessions...")
    alice_session = Session.initialize_alice(shared_secret, bob.public_key)
    bob_session = Session.initialize_bob(shared_secret, bob.private_key)
    print("✓ Sessions initialized\n")
    
    # Alice sends first message
    print("2. Alice sends: 'Hello Bob!'")
    message1 = "Hello Bob!"
    payload1, alice_state = encrypt_message_ratchet(message1, alice_session.get_state_dict())
    print(f"   Encrypted payload version: {payload1.version}")
    print(f"   Message number: {payload1.message_number}")
    
    # Bob receives
    decrypted1, bob_state = decrypt_message_ratchet(payload1, bob_session.get_state_dict())
    print(f"✓ Bob received: '{decrypted1}'")
    assert decrypted1 == message1, "Message 1 mismatch"
    print()
    
    # Update sessions
    alice_session = Session.from_state_dict(alice_state)
    bob_session = Session.from_state_dict(bob_state)
    
    # Bob replies
    print("3. Bob sends: 'Hi Alice!'")
    message2 = "Hi Alice!"
    payload2, bob_state = encrypt_message_ratchet(message2, bob_session.get_state_dict())
    print(f"   Message number: {payload2.message_number}")
    
    # Alice receives
    decrypted2, alice_state = decrypt_message_ratchet(payload2, alice_session.get_state_dict())
    print(f"✓ Alice received: '{decrypted2}'")
    assert decrypted2 == message2, "Message 2 mismatch"
    print()
    
    # Update sessions
    alice_session = Session.from_state_dict(alice_state)
    bob_session = Session.from_state_dict(bob_state)
    
    # Multiple messages in a row
    print("4. Alice sends multiple messages...")
    messages = ["Message 1", "Message 2", "Message 3"]
    payloads = []
    
    for i, msg in enumerate(messages):
        payload, alice_state = encrypt_message_ratchet(msg, alice_state)
        payloads.append(payload)
        print(f"   Sent: '{msg}' (msg_num={payload.message_number})")
    
    print("\n5. Bob receives them in order...")
    for i, (msg, payload) in enumerate(zip(messages, payloads)):
        decrypted, bob_state = decrypt_message_ratchet(payload, bob_state)
        print(f"   Received: '{decrypted}'")
        assert decrypted == msg, f"Message {i} mismatch"
    
    print("\n✓ All tests passed!")


async def test_out_of_order():
    """Test out-of-order message delivery"""
    print("\n\n=== Testing Out-of-Order Message Delivery ===\n")
    
    # Setup
    alice = create_identity("Alice")
    bob = create_identity("Bob")
    shared_secret = derive_shared_secret(alice.private_key, bob.public_key)
    
    alice_session = Session.initialize_alice(shared_secret, bob.public_key)
    bob_session = Session.initialize_bob(shared_secret, bob.private_key)
    
    # Alice sends 3 messages
    print("1. Alice sends 3 messages...")
    messages = ["First", "Second", "Third"]
    payloads = []
    alice_state = alice_session.get_state_dict()
    
    for msg in messages:
        payload, alice_state = encrypt_message_ratchet(msg, alice_state)
        payloads.append(payload)
        print(f"   Sent: '{msg}' (msg_num={payload.message_number})")
    
    # Bob receives them out of order: 3, 1, 2
    print("\n2. Bob receives them out of order (3, 1, 2)...")
    bob_state = bob_session.get_state_dict()
    
    # Receive third message first
    decrypted, bob_state = decrypt_message_ratchet(payloads[2], bob_state)
    print(f"   Received: '{decrypted}' (expected: 'Third')")
    assert decrypted == messages[2]
    
    # Receive first message
    decrypted, bob_state = decrypt_message_ratchet(payloads[0], bob_state)
    print(f"   Received: '{decrypted}' (expected: 'First')")
    assert decrypted == messages[0]
    
    # Receive second message
    decrypted, bob_state = decrypt_message_ratchet(payloads[1], bob_state)
    print(f"   Received: '{decrypted}' (expected: 'Second')")
    assert decrypted == messages[1]
    
    print("\n✓ Out-of-order delivery works!")


async def main():
    try:
        await test_basic_exchange()
        await test_out_of_order()
        print("\n\n🎉 All Double Ratchet tests passed!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        exit(1)


if __name__ == "__main__":
    asyncio.run(main())
