__author__ = 'chris'

ALLOWED_TAGS = [
    'a',
    'b',
    'blockquote',
    'em',
    'hr',
    'h2',
    'h3',
    'h4',
    'h5',
    'i',
    'img',
    'li',
    'p',
    'ol',
    'nl',
    'span',
    'strike',
    'strong',
    'ul',
]
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title', 'alt', 'style'],
    'img': ['src', 'width', 'height'],
    'b': ['style'],
    'blockquote': ['style'],
    'em': ['style'],
    'h2': ['style'],
    'h3': ['style'],
    'h4': ['style'],
    'h5': ['style'],
    'i': ['style'],
    'li': ['style'],
    'p': ['style'],
    'ol': ['style'],
    'nl': ['style'],
    'span': ['style'],
    'strike': ['style'],
    'strong': ['style']
}

ALLOWED_STYLES = ['color', 'background']
