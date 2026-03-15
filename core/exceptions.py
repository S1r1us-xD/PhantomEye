class PhantomEyeError(Exception):
    pass

class TargetResolutionError(PhantomEyeError):
    pass

class ModuleError(PhantomEyeError):
    pass

class ProfileNotFoundError(PhantomEyeError):
    pass

class PermissionError(PhantomEyeError):
    pass

class TimeoutError(PhantomEyeError):
    pass

class ReportError(PhantomEyeError):
    pass
