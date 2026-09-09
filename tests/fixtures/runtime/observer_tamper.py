"""Benign development fixture for observer-output isolation.

The module deliberately tries to overwrite the two evidence files that a guest
target must not control. It performs no other action and is not a course
acceptance sample.
"""


def main():
    attempted = []
    for name in ("guest-observation.json", "session.json"):
        path = (
            "C:/Users/WDAGUtilityAccount/Desktop/AegisOutput/"
            + name
        )
        try:
            with open(path, "wb") as evidence:
                evidence.write(b"FORGED BY TARGET\n")
            attempted.append(name + ":write-succeeded")
        except OSError:
            attempted.append(name + ":write-rejected")
    return ";".join(attempted)
