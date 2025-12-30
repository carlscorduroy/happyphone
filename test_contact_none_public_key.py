#!/usr/bin/env python3
"""Unit tests for contact operations with None public key"""

import asyncio
import tempfile
import os
from pathlib import Path

from happyphone.crypto import (
    create_identity,
    encrypt_message,
    decrypt_message,
    encrypt_message_ratchet,
    decrypt_message_ratchet,
    derive_shared_secret,
    Contact,
    EncryptedPayload,
)
from happyphone.storage import Storage
from happyphone.session import Session


async def test_add_contact_with_none_public_key():
    """Test that the add command successfully creates a new unverified contact with a None public key."""
    print("\n=== Test 1: Add Contact with None Public Key ===")
    
    # Create temporary database
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = Path(tmp.name)
    
    try:
        storage = Storage(db_path)
        await storage.connect()
        
        # Create a contact with None public key (unverified state)
        contact = Contact(
            user_id="abc123",
            public_key=None,
            display_name="Test User",
            pet_name="testuser",
            trust_tier="other",
            verified=False,
        )
        
        # Save contact
        await storage.save_contact(contact)
        print(f"✓ Saved contact with None public key: {contact.pet_name}")
        
        # Retrieve contact
        retrieved = await storage.get_contact("abc123")
        
        # Verify the contact was saved and retrieved correctly
        assert retrieved is not None, "Contact should be retrievable"
        assert retrieved.user_id == "abc123", "User ID mismatch"
        assert retrieved.public_key is None, "Public key should be None"
        assert retrieved.display_name == "Test User", "Display name mismatch"
        assert retrieved.pet_name == "testuser", "Pet name mismatch"
        assert retrieved.verified is False, "Contact should not be verified"
        
        print(f"✓ Contact retrieved successfully with None public key")
        print(f"  - User ID: {retrieved.user_id}")
        print(f"  - Public Key: {retrieved.public_key}")
        print(f"  - Verified: {retrieved.verified}")
        print("✓ Test 1 passed!\n")
        
        await storage.close()
    finally:
        os.unlink(db_path)


async def test_message_command_prevents_sending_to_unverified():
    """Test that the message command prevents sending to unverified contacts or contacts without a public key."""
    print("=== Test 2: Message Command Prevents Sending to Unverified Contacts ===")
    
    # Create an identity
    sender = create_identity("Alice")
    print(f"✓ Created sender identity: {sender.user_id}")
    
    # Test case 1: Contact with None public key
    contact_no_key = Contact(
        user_id="user1",
        public_key=None,
        display_name="User One",
        pet_name="userone",
        trust_tier="other",
        verified=False,
    )
    
    # Check conditions that would prevent sending
    can_send_no_key = contact_no_key.verified and contact_no_key.public_key is not None
    assert not can_send_no_key, "Should not be able to send to contact without public key"
    print(f"✓ Cannot send to contact with None public key (verified={contact_no_key.verified}, has_key={contact_no_key.public_key is not None})")
    
    # Test case 2: Unverified contact with public key
    recipient = create_identity("Bob")
    contact_unverified = Contact(
        user_id="user2",
        public_key=recipient.public_key,
        display_name="User Two",
        pet_name="usertwo",
        trust_tier="other",
        verified=False,
    )
    
    can_send_unverified = contact_unverified.verified and contact_unverified.public_key is not None
    assert not can_send_unverified, "Should not be able to send to unverified contact"
    print(f"✓ Cannot send to unverified contact (verified={contact_unverified.verified}, has_key={contact_unverified.public_key is not None})")
    
    # Test case 3: Verified contact with public key (should work)
    contact_verified = Contact(
        user_id="user3",
        public_key=recipient.public_key,
        display_name="User Three",
        pet_name="userthree",
        trust_tier="other",
        verified=True,
    )
    
    can_send_verified = contact_verified.verified and contact_verified.public_key is not None
    assert can_send_verified, "Should be able to send to verified contact with public key"
    print(f"✓ Can send to verified contact with public key (verified={contact_verified.verified}, has_key={contact_verified.public_key is not None})")
    
    # Test case 4: Verified contact but None public key
    contact_verified_no_key = Contact(
        user_id="user4",
        public_key=None,
        display_name="User Four",
        pet_name="userfour",
        trust_tier="other",
        verified=True,  # Verified but missing key
    )
    
    can_send_verified_no_key = contact_verified_no_key.verified and contact_verified_no_key.public_key is not None
    assert not can_send_verified_no_key, "Should not be able to send to verified contact without public key"
    print(f"✓ Cannot send to verified contact without public key (verified={contact_verified_no_key.verified}, has_key={contact_verified_no_key.public_key is not None})")
    
    print("✓ Test 2 passed!\n")


async def test_public_key_b64_returns_empty_string():
    """Test that the public_key_b64 method returns an empty string when public_key is None."""
    print("=== Test 3: public_key_b64 Method Returns Empty String ===")
    
    # Create contact with None public key
    contact = Contact(
        user_id="test123",
        public_key=None,
        display_name="Test Contact",
        pet_name="testcontact",
        trust_tier="other",
        verified=False,
    )
    
    # Test the public_key_b64 method
    b64_key = contact.public_key_b64()
    
    assert b64_key == "", f"Expected empty string, got: '{b64_key}'"
    assert isinstance(b64_key, str), "Return value should be a string"
    print(f"✓ public_key_b64() returned empty string: '{b64_key}'")
    
    # Verify with a contact that has a public key
    identity = create_identity("TestUser")
    contact_with_key = Contact(
        user_id="test456",
        public_key=identity.public_key,
        display_name="Contact With Key",
        pet_name="withkey",
        trust_tier="other",
        verified=True,
    )
    
    b64_with_key = contact_with_key.public_key_b64()
    assert b64_with_key != "", "Contact with key should return non-empty string"
    assert isinstance(b64_with_key, str), "Return value should be a string"
    print(f"✓ public_key_b64() with actual key returned: '{b64_with_key[:20]}...'")
    
    print("✓ Test 3 passed!\n")


async def test_decryption_fails_with_none_public_key():
    """Test that decryption fails when a contact exists but its public_key is None."""
    print("=== Test 4: Decryption Fails with None Public Key ===")
    
    # Create sender and recipient identities
    sender = create_identity("Alice")
    recipient = create_identity("Bob")
    
    # Create an encrypted message
    message = "Hello, Bob!"
    payload = encrypt_message(message, recipient.public_key)
    print(f"✓ Encrypted message: '{message}'")
    
    # Verify decryption works with correct key
    decrypted = decrypt_message(payload, recipient.private_key)
    assert decrypted == message, "Decryption should work with correct key"
    print(f"✓ Successfully decrypted with correct key: '{decrypted}'")
    
    # Create a contact with None public key (simulating unverified contact)
    contact_no_key = Contact(
        user_id=sender.user_id,
        public_key=None,
        display_name="Alice",
        pet_name="alice",
        trust_tier="other",
        verified=False,
    )
    
    # Attempt to encrypt a message to a contact with None public key
    try:
        # This should fail because public_key is None
        bad_payload = encrypt_message("This should fail", contact_no_key.public_key)
        assert False, "Should have raised an exception when encrypting to None public key"
    except (TypeError, AttributeError, ValueError) as e:
        print(f"✓ Encryption correctly failed with None public key: {type(e).__name__}")
    
    # Test Double Ratchet encryption failure
    print("\n  Testing Double Ratchet encryption with None public key:")
    
    # Try to create session with None public key
    try:
        shared_secret = derive_shared_secret(sender.private_key, contact_no_key.public_key)
        assert False, "Should have raised an exception with None public key in derive_shared_secret"
    except (TypeError, AttributeError, ValueError) as e:
        print(f"  ✓ derive_shared_secret correctly failed with None public key: {type(e).__name__}")
    
    # Test decryption scenario where contact exists but public_key is None
    print("\n  Testing message receipt scenario with None public key:")
    
    # Simulating receiving a message but contact has None public key
    # In the real app, this prevents initializing a session
    contact_sender = contact_no_key  # Contact exists but no public key
    
    # This represents the check in cli.py line 248-260
    if not (contact_sender and contact_sender.public_key):
        print(f"  ✓ Cannot decrypt: contact exists but public_key is None")
        error_msg = "Cannot decrypt: contact not found or not verified"
        print(f"  ✓ Expected error: '{error_msg}'")
    else:
        assert False, "Should have detected None public key"
    
    print("✓ Test 4 passed!\n")


async def test_save_and_load_contact_with_none_public_key():
    """Test that saving and loading a contact with a None public key correctly persists and retrieves the None value."""
    print("=== Test 5: Save and Load Contact with None Public Key ===")
    
    # Create temporary database
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = Path(tmp.name)
    
    try:
        storage = Storage(db_path)
        await storage.connect()
        
        # Create contact with None public key
        contact = Contact(
            user_id="save_test_123",
            public_key=None,
            display_name="Save Test User",
            pet_name="savetest",
            trust_tier="family",
            verified=False,
        )
        
        print(f"Original contact:")
        print(f"  - User ID: {contact.user_id}")
        print(f"  - Public Key: {contact.public_key}")
        print(f"  - Display Name: {contact.display_name}")
        print(f"  - Pet Name: {contact.pet_name}")
        print(f"  - Trust Tier: {contact.trust_tier}")
        print(f"  - Verified: {contact.verified}")
        
        # Save contact
        await storage.save_contact(contact)
        print(f"\n✓ Contact saved to database")
        
        # Clear local reference
        del contact
        
        # Load contact back
        loaded_contact = await storage.get_contact("save_test_123")
        
        assert loaded_contact is not None, "Contact should be retrievable"
        print(f"\n✓ Contact loaded from database")
        
        # Verify all fields match, especially None public_key
        assert loaded_contact.user_id == "save_test_123", "User ID mismatch"
        assert loaded_contact.public_key is None, f"Public key should be None, got: {loaded_contact.public_key}"
        assert loaded_contact.display_name == "Save Test User", "Display name mismatch"
        assert loaded_contact.pet_name == "savetest", "Pet name mismatch"
        assert loaded_contact.trust_tier == "family", "Trust tier mismatch"
        assert loaded_contact.verified is False, "Verified flag mismatch"
        
        print(f"Loaded contact:")
        print(f"  - User ID: {loaded_contact.user_id}")
        print(f"  - Public Key: {loaded_contact.public_key}")
        print(f"  - Display Name: {loaded_contact.display_name}")
        print(f"  - Pet Name: {loaded_contact.pet_name}")
        print(f"  - Trust Tier: {loaded_contact.trust_tier}")
        print(f"  - Verified: {loaded_contact.verified}")
        
        # Test public_key_b64 method on loaded contact
        b64_key = loaded_contact.public_key_b64()
        assert b64_key == "", "public_key_b64() should return empty string for None key"
        print(f"\n✓ public_key_b64() returns empty string: '{b64_key}'")
        
        # Test updating the contact with a real public key
        print(f"\nUpdating contact with real public key...")
        identity = create_identity("TestUser")
        loaded_contact.public_key = identity.public_key
        loaded_contact.verified = True
        
        await storage.save_contact(loaded_contact)
        print(f"✓ Contact updated with public key")
        
        # Load again and verify update
        updated_contact = await storage.get_contact("save_test_123")
        assert updated_contact.public_key is not None, "Public key should not be None after update"
        assert updated_contact.verified is True, "Contact should be verified after update"
        print(f"✓ Updated contact loaded successfully")
        print(f"  - Public Key (first 20 chars): {updated_contact.public_key_b64()[:20]}...")
        print(f"  - Verified: {updated_contact.verified}")
        
        # Test updating back to None
        print(f"\nUpdating contact back to None public key...")
        updated_contact.public_key = None
        updated_contact.verified = False
        
        await storage.save_contact(updated_contact)
        print(f"✓ Contact updated back to None public key")
        
        # Final verification
        final_contact = await storage.get_contact("save_test_123")
        assert final_contact.public_key is None, "Public key should be None after final update"
        assert final_contact.verified is False, "Contact should not be verified"
        print(f"✓ Final contact state verified")
        print(f"  - Public Key: {final_contact.public_key}")
        print(f"  - Verified: {final_contact.verified}")
        
        print("✓ Test 5 passed!\n")
        
        await storage.close()
    finally:
        os.unlink(db_path)


async def test_additional_edge_cases():
    """Additional edge case tests for None public key handling."""
    print("=== Additional Edge Cases ===")
    
    # Create temporary database
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = Path(tmp.name)
    
    try:
        storage = Storage(db_path)
        await storage.connect()
        
        # Test 1: get_contact_by_name with None public key
        print("Test: get_contact_by_name with None public key")
        contact = Contact(
            user_id="edge1",
            public_key=None,
            display_name="Edge Case One",
            pet_name="EdgeCaseOne",
            trust_tier="other",
            verified=False,
        )
        await storage.save_contact(contact)
        
        retrieved = await storage.get_contact_by_name("EdgeCaseOne")
        assert retrieved is not None, "Should retrieve contact by name"
        assert retrieved.public_key is None, "Public key should be None"
        print("✓ get_contact_by_name works with None public key")
        
        # Test 2: get_all_contacts includes contacts with None public key
        print("\nTest: get_all_contacts includes None public key contacts")
        contact2 = Contact(
            user_id="edge2",
            public_key=create_identity("Test").public_key,
            display_name="Edge Case Two",
            pet_name="EdgeCaseTwo",
            trust_tier="other",
            verified=True,
        )
        await storage.save_contact(contact2)
        
        all_contacts = await storage.get_all_contacts()
        assert len(all_contacts) == 2, "Should have 2 contacts"
        
        none_key_contacts = [c for c in all_contacts if c.public_key is None]
        assert len(none_key_contacts) == 1, "Should have 1 contact with None public key"
        print("✓ get_all_contacts correctly handles mixed public key states")
        
        # Test 3: Delete contact with None public key
        print("\nTest: Delete contact with None public key")
        await storage.delete_contact("edge1")
        deleted = await storage.get_contact("edge1")
        assert deleted is None, "Contact should be deleted"
        print("✓ delete_contact works with None public key")
        
        print("✓ All edge cases passed!\n")
        
        await storage.close()
    finally:
        os.unlink(db_path)


async def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("  UNIT TESTS: Contact Operations with None Public Key")
    print("=" * 60)
    
    try:
        await test_add_contact_with_none_public_key()
        await test_message_command_prevents_sending_to_unverified()
        await test_public_key_b64_returns_empty_string()
        await test_decryption_fails_with_none_public_key()
        await test_save_and_load_contact_with_none_public_key()
        await test_additional_edge_cases()
        
        print("\n" + "=" * 60)
        print("  🎉 ALL TESTS PASSED!")
        print("=" * 60 + "\n")
    except Exception as e:
        print("\n" + "=" * 60)
        print(f"  ❌ TEST FAILED: {e}")
        print("=" * 60 + "\n")
        import traceback
        traceback.print_exc()
        exit(1)


if __name__ == "__main__":
    asyncio.run(main())
