"""ADAPTIX unified module. Migrated from tested running code."""


def log(state, message):
    return [*state.get('events', []), message]
