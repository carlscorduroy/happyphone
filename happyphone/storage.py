"""SQLite storage for identity, contacts, and messages"""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Optional
import aiosqlite

from nacl.encoding import Base64Encoder

from .config import DB_PATH, MESSAGE_EXPIRATION_SECONDS
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
                public_key TEXT,
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
                expires_at INTEGER,
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

            CREATE TABLE IF NOT EXISTS skipped_message_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_user_id TEXT NOT NULL,
                dh_public BLOB NOT NULL,
                msg_num INTEGER NOT NULL,
                message_key BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (contact_user_id) REFERENCES contacts(user_id) ON DELETE CASCADE,
                UNIQUE(contact_user_id, dh_public, msg_num)
            );

            CREATE INDEX IF NOT EXISTS idx_skipped_keys_contact ON skipped_message_keys(contact_user_id);
        """)
        await self._db.commit()
        
        # Run migrations for existing databases
        await self._run_migrations()

    async def _run_migrations(self):
        """Run database migrations for schema updates"""
        # Check if expires_at column exists in messages table
        async with self._db.execute("PRAGMA table_info(messages)") as cursor:
            columns = [row['name'] async for row in cursor]
            
        if 'expires_at' not in columns:
            await self._db.execute(
                "ALTER TABLE messages ADD COLUMN expires_at INTEGER"
            )
            await self._db.commit()
            
        # Ensure index exists (now that we're sure the column exists)
        await self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages(expires_at)"
        )
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
        public_key_str = None
        if contact.public_key is not None:
            public_key_str = Base64Encoder.encode(contact.public_key).decode('ascii')
        
        await self._db.execute("""
            INSERT OR REPLACE INTO contacts 
            (user_id, public_key, display_name, pet_name, trust_tier, verified)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            contact.user_id,
            public_key_str,
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
        public_key = None
        if row['public_key'] is not None:
            public_key = Base64Encoder.decode(row['public_key'].encode('ascii'))
        
        return Contact(
            user_id=row['user_id'],
            public_key=public_key,
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
        status: str = 'sent',
        expires_in: int = None
    ):
        """Save a message with optional expiration
        
        Args:
            expires_in: Seconds until message expires. None uses default from config.
                       0 means no expiration.
        """
        # Calculate expiration timestamp
        if expires_in is None:
            expires_in = MESSAGE_EXPIRATION_SECONDS
        
        expires_at = None
        if expires_in > 0:
            expires_at = timestamp + (expires_in * 1000)  # Convert to milliseconds
        
        await self._db.execute("""
            INSERT OR REPLACE INTO messages 
            (id, contact_id, direction, content, timestamp, status, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (message_id, contact_id, direction, content, timestamp, status, expires_at))
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

    async def delete_expired_messages(self) -> int:
        """Delete all expired messages and return count deleted"""
        now_ms = int(datetime.now().timestamp() * 1000)
        cursor = await self._db.execute(
            "DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at < ?",
            (now_ms,)
        )
        deleted = cursor.rowcount
        await self._db.commit()
        return deleted

    async def delete_message(self, message_id: str):
        """Delete a specific message"""
        await self._db.execute("DELETE FROM messages WHERE id = ?", (message_id,))
        await self._db.commit()

    # === Session State Operations ===

    async def save_session_state(self, contact_user_id: str, state_dict: dict):
        """Save or update session state for a contact, including skipped message keys"""
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
        
        # Save skipped message keys
        skipped_keys = state_dict.get('skipped_message_keys', {})
        if skipped_keys:
            # Clear existing keys for this contact and re-insert
            await self._db.execute(
                "DELETE FROM skipped_message_keys WHERE contact_user_id = ?",
                (contact_user_id,)
            )
            for key_str, message_key in skipped_keys.items():
                dh_public_hex, msg_num_str = key_str.split(':', 1)
                dh_public = bytes.fromhex(dh_public_hex)
                msg_num = int(msg_num_str)
                await self._db.execute("""
                    INSERT INTO skipped_message_keys 
                    (contact_user_id, dh_public, msg_num, message_key)
                    VALUES (?, ?, ?, ?)
                """, (contact_user_id, dh_public, msg_num, message_key))
        
        await self._db.commit()

    async def get_session_state(self, contact_user_id: str) -> Optional[dict]:
        """Get session state for a contact, including skipped message keys"""
        async with self._db.execute(
            "SELECT * FROM session_state WHERE contact_user_id = ?",
            (contact_user_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            
            # Load skipped message keys
            skipped_keys = {}
            async with self._db.execute(
                "SELECT dh_public, msg_num, message_key FROM skipped_message_keys WHERE contact_user_id = ?",
                (contact_user_id,)
            ) as key_cursor:
                async for key_row in key_cursor:
                    dh_public_hex = key_row['dh_public'].hex()
                    msg_num = key_row['msg_num']
                    key_str = f"{dh_public_hex}:{msg_num}"
                    skipped_keys[key_str] = key_row['message_key']
            
            return {
                'root_key': row['root_key'],
                'sending_chain_key': row['sending_chain_key'],
                'receiving_chain_key': row['receiving_chain_key'],
                'dh_self_private': row['dh_self_private'],
                'dh_remote_public': row['dh_remote_public'],
                'sending_msg_num': row['sending_msg_num'],
                'receiving_msg_num': row['receiving_msg_num'],
                'previous_sending_chain_length': row['previous_sending_chain_length'],
                'skipped_message_keys': skipped_keys,
            }

    async def delete_session_state(self, contact_user_id: str):
        """Delete session state for a contact"""
        await self._db.execute(
            "DELETE FROM skipped_message_keys WHERE contact_user_id = ?",
            (contact_user_id,)
        )
        await self._db.execute(
            "DELETE FROM session_state WHERE contact_user_id = ?",
            (contact_user_id,)
        )
        await self._db.commit()


# Global storage instance
storage = Storage()
