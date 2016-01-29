def looping_retry(func, *args):
    while True:
        try:
            return func(*args)
        except Exception:
            pass
