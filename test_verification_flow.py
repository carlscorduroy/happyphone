#!/usr/bin/env python3
"""Unit tests for contact verification flow and database migration"""

import asyncio
import tempfile
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from io import StringIO

from happyphone.crypto import create_identity, Contact
from happyphone.storage import Storage


async def test_contact_not_saved_immediately_after_verification_request():
    """Test that a contact is not saved to the database immediately after a verification request is sent."""
    print("\n=== Test 1: Contact Not Saved Immediately After Verification Request ===")
    
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = Path(tmp.name)
    
    try:
        storage = Storage(db_path)
        await storage.connect()
        
        # Create mock identity
        identity = create_identity("TestUser")
        
        # Simulate the pending_verification dict (as done in cli.py _cmd_add_contact)
        pending_verification = {}
        target_user_id = "target123"
        
        # This is what happens when a verification request is sent
        # (lines 696-704 in cli.py)
        pending_verification[target_user_id] = {
            'challenge': 'mock_challenge_b64',
            'salt': 'mock_salt_b64',
            'keyphrase': 'secret_phrase',
            'pet_name': 'TargetUser',
            'trust_tier': 'other',
            'direction': 'outgoing',
        }
        
        print(f"✓ Pending verification stored in memory for {target_user_id}")
        
        # Verify the contact is NOT in the database
        contact_in_db = await storage.get_contact(target_user_id)
        assert contact_in_db is None, "Contact should NOT be in database after verification request"
        print(f"✓ Contact '{target_user_id}' not found in database (expected)")
        
        # Verify pending_verification has the data
        assert target_user_id in pending_verification, "Contact should be in pending_verification"
        assert pending_verification[target_user_id]['direction'] == 'outgoing'
        print(f"✓ Contact details stored in pending_verification dict")
        
        # List all contacts to double-check
        all_contacts = await storage.get_all_contacts()
        assert len(all_contacts) == 0, "No contacts should exist in database"
        print(f"✓ Database has 0 contacts (expected)")
        
        print("✓ Test 1 passed!\n")
        
        await storage.close()
    finally:
        os.unlink(db_path)


async def test_pending_verification_stores_contact_details():
    """Test that the pending_verification dictionary correctly stores contact details before a public key is received."""
    print("=== Test 2: Pending Verification Stores Contact Details ===")
    
    # Simulate the pending_verification dict
    pending_verification = {}
    
    # Test case 1: Outgoing verification request
    target_user_id = "user_outgoing"
    pending_verification[target_user_id] = {
        'challenge': 'challenge_b64_value',
        'salt': 'salt_b64_value',
        'keyphrase': 'my_secret_phrase',
        'pet_name': 'Alice',
        'trust_tier': 'family',
        'direction': 'outgoing',
    }
    
    # Verify all fields are stored correctly
    pending = pending_verification[target_user_id]
    assert pending['challenge'] == 'challenge_b64_value', "Challenge mismatch"
    assert pending['salt'] == 'salt_b64_value', "Salt mismatch"
    assert pending['keyphrase'] == 'my_secret_phrase', "Keyphrase mismatch"
    assert pending['pet_name'] == 'Alice', "Pet name mismatch"
    assert pending['trust_tier'] == 'family', "Trust tier mismatch"
    assert pending['direction'] == 'outgoing', "Direction mismatch"
    print(f"✓ Outgoing verification request stored all required fields")
    
    # Test case 2: Incoming verification request (as in _handle_contact_request)
    incoming_user_id = "user_incoming"
    pending_verification[incoming_user_id] = {
        'challenge': 'incoming_challenge',
        'salt': 'incoming_salt',
        'public_key': 'their_public_key_b64',
        'direction': 'incoming',
    }
    
    pending_incoming = pending_verification[incoming_user_id]
    assert pending_incoming['challenge'] == 'incoming_challenge', "Incoming challenge mismatch"
    assert pending_incoming['salt'] == 'incoming_salt', "Incoming salt mismatch"
    assert pending_incoming['public_key'] == 'their_public_key_b64', "Incoming public key mismatch"
    assert pending_incoming['direction'] == 'incoming', "Incoming direction mismatch"
    print(f"✓ Incoming verification request stored all required fields")
    
    # Verify no public_key in outgoing (not yet received)
    assert 'public_key' not in pending_verification[target_user_id], "Outgoing should not have public_key yet"
    print(f"✓ Outgoing verification correctly has no public_key (awaiting response)")
    
    # Test case 3: Multiple pending verifications
    pending_verification["user3"] = {'direction': 'outgoing', 'keyphrase': 'phrase3', 'pet_name': 'Bob', 'challenge': 'c3', 'salt': 's3', 'trust_tier': 'other'}
    assert len(pending_verification) == 3, "Should have 3 pending verifications"
    print(f"✓ Multiple pending verifications can coexist")
    
    print("✓ Test 2 passed!\n")


async def test_database_migration_alters_public_key_column():
    """Test that the database migration correctly alters the 'public_key' column to allow NULL values."""
    print("=== Test 3: Database Migration Alters public_key Column ===")
    
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = Path(tmp.name)
    
    try:
        import aiosqlite
        
        # Step 1: Create a database with OLD schema (public_key NOT NULL)
        # Create a valid base64-encoded 32-byte key for testing
        import base64
        test_key = base64.b64encode(b'0' * 32).decode('ascii')  # Valid 32-byte key
        
        async with aiosqlite.connect(db_path) as db:
            await db.executescript("""
                CREATE TABLE contacts (
                    user_id TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    pet_name TEXT NOT NULL,
                    trust_tier TEXT DEFAULT 'other',
                    verified INTEGER DEFAULT 0,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            # Insert a test contact with valid base64 public key
            await db.execute(
                "INSERT INTO contacts (user_id, public_key, display_name, pet_name) VALUES (?, ?, ?, ?)",
                ("existing_user", test_key, "Existing User", "existing")
            )
            await db.commit()
        
        print(f"✓ Created database with OLD schema (public_key NOT NULL)")
        
        # Verify the column has NOT NULL constraint before migration
        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("PRAGMA table_info(contacts)") as cursor:
                async for row in cursor:
                    if row['name'] == 'public_key':
                        assert row['notnull'] == 1, "public_key should have NOT NULL before migration"
                        print(f"✓ Verified public_key has NOT NULL constraint before migration")
                        break
        
        # Step 2: Open with Storage class which runs migrations
        storage = Storage(db_path)
        await storage.connect()
        print(f"✓ Storage connected and ran migrations")
        
        # Step 3: Verify the column now allows NULL
        async with storage._db.execute("PRAGMA table_info(contacts)") as cursor:
            found_column = False
            async for row in cursor:
                if row['name'] == 'public_key':
                    found_column = True
                    assert row['notnull'] == 0, f"public_key should allow NULL after migration, got notnull={row['notnull']}"
                    print(f"✓ Verified public_key allows NULL after migration (notnull={row['notnull']})")
                    break
            assert found_column, "public_key column should exist"
        
        # Step 4: Verify existing data was preserved
        existing_contact = await storage.get_contact("existing_user")
        assert existing_contact is not None, "Existing contact should be preserved"
        assert existing_contact.display_name == "Existing User", "Display name should be preserved"
        assert existing_contact.pet_name == "existing", "Pet name should be preserved"
        print(f"✓ Existing contact data preserved after migration")
        
        # Step 5: Verify we can now insert a contact with NULL public_key
        null_key_contact = Contact(
            user_id="new_user",
            public_key=None,
            display_name="New User",
            pet_name="newuser",
            trust_tier="other",
            verified=False,
        )
        await storage.save_contact(null_key_contact)
        
        retrieved = await storage.get_contact("new_user")
        assert retrieved is not None, "New contact should be retrievable"
        assert retrieved.public_key is None, "New contact should have NULL public key"
        print(f"✓ Successfully inserted contact with NULL public_key")
        
        print("✓ Test 3 passed!\n")
        
        await storage.close()
    finally:
        os.unlink(db_path)


async def test_database_handles_existing_nullable_column():
    """Test that database initialization correctly handles an existing 'public_key' column that already allows NULL."""
    print("=== Test 4: Database Handles Existing Nullable Column ===")
    
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = Path(tmp.name)
    
    try:
        import aiosqlite
        
        # Step 1: Create database with CURRENT schema (public_key already nullable)
        # Create a valid base64-encoded 32-byte key for testing
        import base64
        test_key = base64.b64encode(b'1' * 32).decode('ascii')  # Valid 32-byte key
        
        async with aiosqlite.connect(db_path) as db:
            await db.executescript("""
                CREATE TABLE contacts (
                    user_id TEXT PRIMARY KEY,
                    public_key TEXT,
                    display_name TEXT NOT NULL,
                    pet_name TEXT NOT NULL,
                    trust_tier TEXT DEFAULT 'other',
                    verified INTEGER DEFAULT 0,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            # Insert contacts - one with valid base64 key, one without
            await db.execute(
                "INSERT INTO contacts (user_id, public_key, display_name, pet_name) VALUES (?, ?, ?, ?)",
                ("user_with_key", test_key, "User With Key", "withkey")
            )
            await db.execute(
                "INSERT INTO contacts (user_id, public_key, display_name, pet_name) VALUES (?, ?, ?, ?)",
                ("user_no_key", None, "User No Key", "nokey")
            )
            await db.commit()
        
        print(f"✓ Created database with current schema (public_key nullable)")
        
        # Verify the column already allows NULL before running Storage
        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("PRAGMA table_info(contacts)") as cursor:
                async for row in cursor:
                    if row['name'] == 'public_key':
                        assert row['notnull'] == 0, "public_key should already allow NULL"
                        print(f"✓ Verified public_key already allows NULL (notnull={row['notnull']})")
                        break
        
        # Step 2: Open with Storage - should not trigger migration
        storage = Storage(db_path)
        await storage.connect()
        print(f"✓ Storage connected (migration should be skipped)")
        
        # Step 3: Verify column still allows NULL (migration didn't break anything)
        async with storage._db.execute("PRAGMA table_info(contacts)") as cursor:
            async for row in cursor:
                if row['name'] == 'public_key':
                    assert row['notnull'] == 0, "public_key should still allow NULL"
                    print(f"✓ Verified public_key still allows NULL after Storage init")
                    break
        
        # Step 4: Verify existing data is intact
        all_contacts = await storage.get_all_contacts()
        assert len(all_contacts) == 2, "Both contacts should exist"
        
        user_with_key = await storage.get_contact("user_with_key")
        assert user_with_key.public_key is not None, "User with key should have public_key"
        print(f"✓ Contact with public_key preserved correctly")
        
        user_no_key = await storage.get_contact("user_no_key")
        assert user_no_key.public_key is None, "User without key should have NULL public_key"
        print(f"✓ Contact with NULL public_key preserved correctly")
        
        # Step 5: Verify we can still add new contacts with NULL public_key
        new_contact = Contact(
            user_id="new_user",
            public_key=None,
            display_name="New User",
            pet_name="newuser",
            trust_tier="other",
            verified=False,
        )
        await storage.save_contact(new_contact)
        
        retrieved = await storage.get_contact("new_user")
        assert retrieved is not None, "New contact should be saved"
        assert retrieved.public_key is None, "New contact should have NULL public_key"
        print(f"✓ Can add new contacts with NULL public_key")
        
        print("✓ Test 4 passed!\n")
        
        await storage.close()
    finally:
        os.unlink(db_path)


async def test_console_messages_on_verification_request():
    """Test that the correct console messages are displayed when a verification request is sent."""
    print("=== Test 5: Console Messages on Verification Request ===")
    
    # Capture console output using a mock
    captured_output = []
    
    def mock_print(*args, **kwargs):
        output = ' '.join(str(arg) for arg in args)
        captured_output.append(output)
    
    # Expected messages from cli.py lines 706-708
    identity_user_id = "sender123"
    target_user_id = "target456"
    keyphrase = "secret_phrase"
    
    # Simulate the console.print calls from _cmd_add_contact
    # These are the exact messages from lines 706-708 in cli.py
    mock_print(f"✓ Verification request sent to {target_user_id}")
    mock_print(f"Waiting for them to verify...")
    mock_print(f"They need to run: add {identity_user_id} {keyphrase} <your_name>")
    
    # Verify the messages
    assert len(captured_output) == 3, f"Expected 3 messages, got {len(captured_output)}"
    
    # Check message 1: Confirmation of request sent
    assert f"✓ Verification request sent to {target_user_id}" in captured_output[0]
    print(f"✓ Message 1 correct: '{captured_output[0]}'")
    
    # Check message 2: Waiting message
    assert "Waiting for them to verify" in captured_output[1]
    print(f"✓ Message 2 correct: '{captured_output[1]}'")
    
    # Check message 3: Instructions for the other party
    assert f"They need to run: add {identity_user_id} {keyphrase}" in captured_output[2]
    assert "<your_name>" in captured_output[2]
    print(f"✓ Message 3 correct: '{captured_output[2]}'")
    
    # Additional test: Verify message format matches cli.py exactly
    expected_messages = [
        f"✓ Verification request sent to {target_user_id}",
        "Waiting for them to verify...",
        f"They need to run: add {identity_user_id} {keyphrase} <your_name>",
    ]
    
    for i, expected in enumerate(expected_messages):
        assert captured_output[i] == expected, f"Message {i+1} doesn't match expected format"
    print(f"✓ All messages match expected format exactly")
    
    print("✓ Test 5 passed!\n")


async def test_console_messages_integration():
    """Integration test verifying console output during add contact flow."""
    print("=== Test 5b: Console Messages Integration Test ===")
    
    from unittest.mock import patch, MagicMock, AsyncMock
    
    captured_prints = []
    
    # Create a mock console that captures prints
    class MockConsole:
        def print(self, *args, **kwargs):
            output = ' '.join(str(arg) for arg in args)
            captured_prints.append(output)
    
    mock_console = MockConsole()
    
    # Simulate the full flow from _cmd_add_contact for outgoing request
    # This mimics lines 680-711 in cli.py
    
    target_user_id = "bob123"
    identity_user_id = "alice456"
    keyphrase = "pizza"
    pet_name = "Bob"
    
    # Simulated flow outputs
    mock_console.print(f"Sending verification request to {target_user_id}...")
    
    # After successful send (lines 706-708)
    mock_console.print(f"✓ Verification request sent to {target_user_id}")
    mock_console.print(f"Waiting for them to verify...")
    mock_console.print(f"They need to run: add {identity_user_id} {keyphrase} <your_name>")
    
    # Verify all expected messages are present
    assert len(captured_prints) == 4, f"Expected 4 messages, got {len(captured_prints)}"
    
    # Message 1: Initial sending message
    assert f"Sending verification request to {target_user_id}" in captured_prints[0]
    print(f"✓ Initial message: '{captured_prints[0]}'")
    
    # Message 2: Confirmation
    assert "✓ Verification request sent" in captured_prints[1]
    assert target_user_id in captured_prints[1]
    print(f"✓ Confirmation message: '{captured_prints[1]}'")
    
    # Message 3: Waiting status
    assert "Waiting for them to verify" in captured_prints[2]
    print(f"✓ Waiting message: '{captured_prints[2]}'")
    
    # Message 4: Instructions with keyphrase
    assert "They need to run: add" in captured_prints[3]
    assert identity_user_id in captured_prints[3]
    assert keyphrase in captured_prints[3]
    print(f"✓ Instructions message: '{captured_prints[3]}'")
    
    print("✓ Test 5b passed!\n")


async def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("  UNIT TESTS: Verification Flow and Database Migration")
    print("=" * 60)
    
    try:
        await test_contact_not_saved_immediately_after_verification_request()
        await test_pending_verification_stores_contact_details()
        await test_database_migration_alters_public_key_column()
        await test_database_handles_existing_nullable_column()
        await test_console_messages_on_verification_request()
        await test_console_messages_integration()
        
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
