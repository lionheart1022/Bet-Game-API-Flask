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


class debug_log:
    def debug_print(meth):
        def doprint(cls, msg, exc_info=(meth=='exception')):
            print('{}: {}'.format(meth.upper(), msg))
            if exc_info:
                import traceback
                traceback.print_exc()
        return doprint
    for meth in 'debug info warning error exception'.split():
        locals()[meth] = classmethod(debug_print(meth))
