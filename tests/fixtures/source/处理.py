def normalize(value):
    if value < 0:
        return 0
    return value


def display(value):
    print("结果", normalize(value))


display(7)
