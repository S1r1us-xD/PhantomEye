import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.exceptions import ModuleError


class Dispatcher:
    def __init__(self, ctx):
        self.ctx = ctx

    def run_module(self, cls, *args, **kwargs):
        try:
            instance = cls(*args, **kwargs)
            instance.run()
            self.ctx.add_findings(instance.findings)
            return instance.findings
        except Exception as exc:
            self.ctx.logger.debug(f"Module {cls.__name__} error: {exc}")
            return []

    def run_parallel(self, tasks):
        results = []
        threads = getattr(self.ctx.args, "threads", 50)
        with ThreadPoolExecutor(max_workers=min(len(tasks), threads)) as executor:
            futures = {executor.submit(fn, *args): name for name, fn, args in tasks}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    results.append((name, result))
                except Exception as exc:
                    self.ctx.logger.debug(f"Task '{name}' failed: {exc}")
        return results

    def run_sequential(self, tasks):
        results = []
        for name, fn, args in tasks:
            try:
                result = fn(*args)
                results.append((name, result))
            except Exception as exc:
                self.ctx.logger.debug(f"Task '{name}' failed: {exc}")
        return results
