def smart_unicode(s, encoding='utf8'):
    """ Convert str to unicode. If s is unicode, return itself. """
    if isinstance(s, unicode):
        return s
    return s.decode(encodinge)


def smart_str(s, encoding='utf8'):
    """ Convert unicode to str. If s is str, return itself. """
    if isinstance(s, str):
        return s
    return s.encode(encodinge)
