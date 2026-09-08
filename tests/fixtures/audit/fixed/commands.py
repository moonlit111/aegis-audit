import subprocess


def inspect_host(host: str) -> str:
    """HTTP form handler; host comes from the submitted form field."""
    if not host or len(host) > 253 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for c in host) or host.startswith("-"):
        raise ValueError("invalid host")
    return subprocess.check_output(["nslookup", host], shell=False, text=True)
