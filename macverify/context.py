import os

from . import shell


class Context(object):
    def __init__(self, timeout=shell.DEFAULT_TIMEOUT, projects=None, verbose=False, lang="en", cwd=None):
        self.timeout = timeout
        self.projects = list(projects or [])
        self.verbose = verbose
        self.lang = lang
        self.cwd = cwd or os.getcwd()

    def slow(self, factor=3):
        return int(self.timeout * factor)


def default_context(ctx=None):
    return ctx if ctx is not None else Context()
