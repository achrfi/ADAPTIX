"""`identity_json_path` is a dotted string, and it must be walked by segment.

Measured on a real lab: with `identity_json_path = "data.username"` every session
failed validation with "Session identity not validated; refresh credentials outside
the planner", although `/me` returned the caller's own name. The cause was iterating
the string one character at a time, so no candidate could ever be validated - an
application with an obvious BOLA reported nothing.
"""
from src.adaptix.tools.discovery import at_path

BODY = {'data': {'username': 'adaptix_owner', 'admin': False, 'email': 'a@b.c'},
        'status': 'success'}


def test_dotted_string_is_split_into_segments():
    assert at_path(BODY, 'data.username') == 'adaptix_owner'


def test_single_segment_string_works():
    assert at_path(BODY, 'status') == 'success'


def test_list_form_is_still_accepted():
    assert at_path(BODY, ['data', 'username']) == 'adaptix_owner'


def test_missing_path_returns_none_not_raises():
    assert at_path(BODY, 'data.nope') is None
    assert at_path(BODY, 'nope.username') is None
    assert at_path({}, 'data.username') is None


def test_empty_path_returns_whole_body():
    assert at_path(BODY, '') == BODY
    assert at_path(BODY, []) == BODY


def test_list_bodies_support_numeric_segments():
    payload = {'users': [{'username': 'first'}, {'username': 'second'}]}
    assert at_path(payload, 'users.1.username') == 'second'
    assert at_path(payload, 'users.9.username') is None
    assert at_path(payload, 'users.x.username') is None


def test_the_first_character_is_never_used_as_a_key():
    """The exact defect: 'd' was looked up instead of 'data'."""
    assert at_path({'d': 'wrong', 'data': {'username': 'right'}}, 'data.username') == 'right'
