import os
from base_agent.paths import BasePaths

class AflPaths(BasePaths):

    @property
    def initial_corpus(self):
        return os.path.join(self.disk_volume, "initial_corpus")

    @property
    def result_corpus(self):
        return os.path.join(self.afl_out, "default", "queue")

    @property
    def merged_corpus(self):
        return os.path.join(self.tmpfs_volume, "merged_corpus") # TODO: maybe disk is fine?

    @property
    def afl_out(self):
        return os.path.join(self.tmpfs_volume, "afl_out")

    @property
    def crashes_dir(self):
        return os.path.join(self.afl_out, "default", "crashes")

    @property
    def hangs_dir(self):
        return os.path.join(self.afl_out, "default", "hangs")

    @property
    def fuzzer_stats(self):
        return os.path.join(self.afl_out, "default", "fuzzer_stats")


    @property
    def showmap_log(self):
        return os.path.join(self.tmpfs_volume, "showmap.log")