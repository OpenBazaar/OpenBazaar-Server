import time


def looping_retry(func, *args):
    while True:
        try:
            return func(*args)
        except Exception:
            time.sleep(0.5)
