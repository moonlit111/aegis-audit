import subprocess


def format_value(value: str) -> str:
    """Format text supplied at this component's input boundary."""
    return subprocess.check_output("printf %s " + value, shell=True, text=True)
