"""SQLite storage for identity, contacts, and messages"""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Optional
import aiosqlite

from nacl.encoding import Base64Encoder

from .config import DB_PATH
from .crypto import Identity, Contact


class Storage:
    """Async SQLite storage manager"""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._db: Optional[aiosqlite.Connection] = None

    async def connect(self):
        """Initialize database connection and create tables"""
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._create_tables()

    async def close(self):
        """Close database connection"""
        if self._db:
            await self._db.close()
            self._db = None

    async def _create_tables(self):
        """Create database tables if they don't exist"""
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS identity (
                user_id TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL,
                display_name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS contacts (
                user_id TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                display_name TEXT NOT NULL,
                pet_name TEXT NOT NULL,
                trust_tier TEXT DEFAULT 'other',
                verified INTEGER DEFAULT 0,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                contact_id TEXT NOT NULL,
                direction TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                status TEXT DEFAULT 'sent',
                FOREIGN KEY (contact_id) REFERENCES contacts(user_id)
            );

            CREATE INDEX IF NOT EXISTS idx_messages_contact ON messages(contact_id);
            CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);

            CREATE TABLE IF NOT EXISTS session_state (
                contact_user_id TEXT PRIMARY KEY,
                root_key BLOB NOT NULL,
                sending_chain_key BLOB,
                receiving_chain_key BLOB,
                dh_self_private BLOB NOT NULL,
                dh_remote_public BLOB,
                sending_msg_num INTEGER DEFAULT 0,
                receiving_msg_num INTEGER DEFAULT 0,
                previous_sending_chain_length INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (contact_user_id) REFERENCES contacts(user_id) ON DELETE CASCADE
            );
        """)
        await self._db.commit()

    # === Identity Operations ===

    async def save_identity(self, identity: Identity):
        """Save or update identity"""
        await self._db.execute("""
            INSERT OR REPLACE INTO identity (user_id, public_key, private_key, display_name)
            VALUES (?, ?, ?, ?)
        """, (
            identity.user_id,
            Base64Encoder.encode(identity.public_key).decode('ascii'),
            Base64Encoder.encode(identity.private_key).decode('ascii'),
            identity.display_name,
        ))
        await self._db.commit()

    async def get_identity(self) -> Optional[Identity]:
        """Get stored identity (there should only be one)"""
        async with self._db.execute("SELECT * FROM identity LIMIT 1") as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            return Identity(
                user_id=row['user_id'],
                public_key=Base64Encoder.decode(row['public_key'].encode('ascii')),
                private_key=Base64Encoder.decode(row['private_key'].encode('ascii')),
                display_name=row['display_name'],
            )

    async def delete_identity(self):
        """Delete identity and all data"""
        await self._db.execute("DELETE FROM identity")
        await self._db.execute("DELETE FROM contacts")
        await self._db.execute("DELETE FROM messages")
        await self._db.commit()

    # === Contact Operations ===

    async def save_contact(self, contact: Contact):
        """Save or update contact"""
        await self._db.execute("""
            INSERT OR REPLACE INTO contacts 
            (user_id, public_key, display_name, pet_name, trust_tier, verified)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            contact.user_id,
            Base64Encoder.encode(contact.public_key).decode('ascii'),
            contact.display_name,
            contact.pet_name,
            contact.trust_tier,
            1 if contact.verified else 0,
        ))
        await self._db.commit()

    async def get_contact(self, user_id: str) -> Optional[Contact]:
        """Get contact by user ID"""
        async with self._db.execute(
            "SELECT * FROM contacts WHERE user_id = ?", (user_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            return self._row_to_contact(row)

    async def get_contact_by_name(self, name: str) -> Optional[Contact]:
        """Get contact by pet name (case-insensitive)"""
        async with self._db.execute(
            "SELECT * FROM contacts WHERE LOWER(pet_name) = LOWER(?)", (name,)
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            return self._row_to_contact(row)

    async def get_all_contacts(self) -> list[Contact]:
        """Get all contacts"""
        contacts = []
        async with self._db.execute("SELECT * FROM contacts ORDER BY pet_name") as cursor:
            async for row in cursor:
                contacts.append(self._row_to_contact(row))
        return contacts

    async def delete_contact(self, user_id: str):
        """Delete contact and their messages"""
        await self._db.execute("DELETE FROM contacts WHERE user_id = ?", (user_id,))
        await self._db.execute("DELETE FROM messages WHERE contact_id = ?", (user_id,))
        await self._db.commit()

    def _row_to_contact(self, row) -> Contact:
        return Contact(
            user_id=row['user_id'],
            public_key=Base64Encoder.decode(row['public_key'].encode('ascii')),
            display_name=row['display_name'],
            pet_name=row['pet_name'],
            trust_tier=row['trust_tier'],
            verified=bool(row['verified']),
        )

    # === Message Operations ===

    async def save_message(
        self,
        message_id: str,
        contact_id: str,
        direction: str,
        content: str,
        timestamp: int,
        status: str = 'sent'
    ):
        """Save a message"""
        await self._db.execute("""
            INSERT OR REPLACE INTO messages 
            (id, contact_id, direction, content, timestamp, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (message_id, contact_id, direction, content, timestamp, status))
        await self._db.commit()

    async def get_messages(self, contact_id: str, limit: int = 50) -> list[dict]:
        """Get messages for a contact, most recent first"""
        messages = []
        async with self._db.execute("""
            SELECT * FROM messages 
            WHERE contact_id = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (contact_id, limit)) as cursor:
            async for row in cursor:
                messages.append({
                    'id': row['id'],
                    'contact_id': row['contact_id'],
                    'direction': row['direction'],
                    'content': row['content'],
                    'timestamp': row['timestamp'],
                    'status': row['status'],
                })
        return list(reversed(messages))  # Return in chronological order

    async def update_message_status(self, message_id: str, status: str):
        """Update message delivery status"""
        await self._db.execute(
            "UPDATE messages SET status = ? WHERE id = ?",
            (status, message_id)
        )
        await self._db.commit()

    # === Session State Operations ===

    async def save_session_state(self, contact_user_id: str, state_dict: dict):
        """Save or update session state for a contact"""
        await self._db.execute("""
            INSERT OR REPLACE INTO session_state (
                contact_user_id, root_key, sending_chain_key, receiving_chain_key,
                dh_self_private, dh_remote_public, sending_msg_num, receiving_msg_num,
                previous_sending_chain_length, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            contact_user_id,
            state_dict['root_key'],
            state_dict['sending_chain_key'],
            state_dict['receiving_chain_key'],
            state_dict['dh_self_private'],
            state_dict['dh_remote_public'],
            state_dict['sending_msg_num'],
            state_dict['receiving_msg_num'],
            state_dict['previous_sending_chain_length'],
        ))
        await self._db.commit()

    async def get_session_state(self, contact_user_id: str) -> Optional[dict]:
        """Get session state for a contact"""
        async with self._db.execute(
            "SELECT * FROM session_state WHERE contact_user_id = ?",
            (contact_user_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            return {
                'root_key': row['root_key'],
                'sending_chain_key': row['sending_chain_key'],
                'receiving_chain_key': row['receiving_chain_key'],
                'dh_self_private': row['dh_self_private'],
                'dh_remote_public': row['dh_remote_public'],
                'sending_msg_num': row['sending_msg_num'],
                'receiving_msg_num': row['receiving_msg_num'],
                'previous_sending_chain_length': row['previous_sending_chain_length'],
                'skipped_message_keys': {},  # Not persisted, will be rebuilt
            }

    async def delete_session_state(self, contact_user_id: str):
        """Delete session state for a contact"""
        await self._db.execute(
            "DELETE FROM session_state WHERE contact_user_id = ?",
            (contact_user_id,)
        )
        await self._db.commit()


# Global storage instance
storage = Storage()
