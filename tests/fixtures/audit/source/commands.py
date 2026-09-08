import subprocess


def inspect_host(host: str) -> str:
    """HTTP form handler; host comes from the submitted form field."""
    return subprocess.check_output("nslookup " + host, shell=True, text=True)
