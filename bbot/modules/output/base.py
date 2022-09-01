import logging

from bbot.modules.base import BaseModule


class BaseOutputModule(BaseModule):
    accept_dupes = True
    _type = "output"
    emit_graph_trail = True
    scope_distance_modifier = None
    _stats_exclude = True

    def _filter_event(self, e):
        # special "FINISHED" event
        if type(e) == str:
            return e == "FINISHED"
        if e._omit:
            return False
        return True if e._force_output else not e._internal

    @property
    def config(self):
        config = self.scan.config.get("output_modules", {}).get(self.name, {})
        if config is None:
            config = {}
        return config

    @property
    def log(self):
        if self._log is None:
            self._log = logging.getLogger(f"bbot.modules.output.{self.name}")
        return self._log
