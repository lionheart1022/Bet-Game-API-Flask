from types import SimpleNamespace
import traceback

class classproperty:
    """
    Cached class property; evaluated only once
    """
    def __init__(self, fget):
        self.fget = fget
        self.obj = {}
    def __get__(self, owner, cls):
        if cls not in self.obj:
            self.obj[cls] = self.fget(cls)
        return self.obj[cls]


debug_log = SimpleNamespace(**{
    meth: lambda msg, exc_info=False: (
        print('{}: {}'.format(meth.upper(), msg))
        or (exc_info or meth == 'exception') and traceback.print_exc()
    ) for meth in
    'debug info warning error exception'.split()
})
