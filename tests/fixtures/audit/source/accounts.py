PRIVATE_ACCOUNTS = {}


def private_profile(session: dict, user_id: str) -> dict:
    """Authenticated /account/<user_id> endpoint for a user's private account data."""
    if not session.get("authenticated"):
        raise PermissionError("login required")
    return PRIVATE_ACCOUNTS[user_id]
