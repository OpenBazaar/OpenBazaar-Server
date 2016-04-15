import bleach

from api import ALLOWED_TAGS, ALLOWED_ATTRIBUTES, ALLOWED_STYLES

# pylint: disable=W1402
def smart_unicode(s, encoding='utf8'):
    """ Convert str to unicode. If s is unicode, return itself.
    >>> smart_unicode('')
    u''
    >>> smart_unicode('abc')
    u'abc'
    >>> smart_unicode('\xe4\xbd\xa0\xe5\xa5\xbd')
    u'\u4f60\u597d'
    >>> smart_unicode(u'abc')
    u'abc'
    >>> smart_unicode(u'\u4f60\u597d')
    u'\u4f60\u597d'
    """
    if isinstance(s, unicode):
        return s
    return s.decode(encoding)


def smart_str(s, encoding='utf8'):
    """ Convert unicode to str. If s is str, return itself.
    >>> smart_str(u'')
    ''
    >>> smart_str(u'abc')
    'abc'
    >>> smart_str(u'\u4f60\u597d') ==  '\xe4\xbd\xa0\xe5\xa5\xbd'
    True
    >>> smart_str('abc')
    'abc'
    >>> smart_str('\xe4\xbd\xa0\xe5\xa5\xbd') == '\xe4\xbd\xa0\xe5\xa5\xbd'
    True
    """
    if isinstance(s, str):
        return s
    return s.encode(encoding)

def sanitize_html(value):
    """ Recursively sanitize all strings within a data structure. """
    if isinstance(value, dict):
        value = {k:sanitize_html(v) for k, v in value.iteritems()}
    elif isinstance(value, list):
        value = [sanitize_html(v) for v in value]
    elif isinstance(value, basestring):
        value = bleach.clean(value, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, styles=ALLOWED_STYLES)
    return value
