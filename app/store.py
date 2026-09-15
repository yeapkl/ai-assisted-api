"""
Demo in-memory user store.
NOTE (flagged in improvement plan): replace with a real database
(e.g. Postgres via SQLAlchemy) before production use. Data does not persist
across restarts and this is not safe for concurrent multi-process deployment.
"""
from dataclasses import dataclass


@dataclass
class User:
    username: str
    hashed_password: str


class UserStore:
    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    def get(self, username: str) -> User | None:
        return self._users.get(username)

    def exists(self, username: str) -> bool:
        return username in self._users

    def create(self, username: str, hashed_password: str) -> User:
        user = User(username=username, hashed_password=hashed_password)
        self._users[username] = user
        return user


user_store = UserStore()
