import logging
from contextlib import suppress
import os
import shutil
from typing import List

from base_agent.abstract import Agent
from base_agent.errors import RemoteFileLookupError
from base_agent.settings import AppSettings, FuzzerMode, ObjectStorage

from base_agent.errors.codes import E_SUCCESS
from base_agent.abstract import AgentMode
from base_agent.settings import AppSettings

from base_agent.kubernetes import UserContainerManager
from base_agent.utils import chmod_recursive, TimeMeasure

from agent.app.config import FuzzerConfig
from agent.app.utils import cleanup_afl_dir

from .paths import *
from base_agent.transfer import FileTransfer

from . import fuzzing
from . import merge
from . import crash

class AgentModeBase(AgentMode):

    _unmerged_corpus_object_keys: List[str]

    _logger: logging.Logger
    _container_mgr: UserContainerManager
    _settings: AppSettings

    transfer: FileTransfer
    paths: AflPaths

    def __init__(
        self,
        run_id: str,
        settings: AppSettings,
        container_mgr: UserContainerManager,
        object_storage: ObjectStorage,
        logger_name: str,
    ):

        self._unmerged_corpus_object_keys = []

        self._logger = logging.getLogger(logger_name)
        self._container_mgr = container_mgr
        self._settings = settings

        self.run_id = run_id
        self.transfer = FileTransfer(object_storage, settings)
        self.paths = AflPaths(settings)

        self.status = None
        self.fuzz_statistics = None
        self.crashes = []


    def _download_binaries(self):
        self.transfer.download_binaries(self.paths.binaries)


    def _download_config(self):
        try:
            self.transfer.download_config(self.paths.config)
        except RemoteFileLookupError:
            self._logger.info("Config not found. Default settings will be used")


    def _download_seeds(self):
        try:
            self.transfer.download_seeds(self.paths.initial_corpus)
        except RemoteFileLookupError:
            self._logger.warning("Seeds not found")


    def _download_merged_corpus(self, must_exist=True):
        try:
            self.transfer.download_merged_corpus(self.paths.initial_corpus)
        except RemoteFileLookupError:
            if must_exist:
                raise
            self._logger.warning("Corpus not found. Assume first launch")



    def _download_unmerged_corpus(self, must_exist=True):
        try:
            keys = self.transfer.download_unmerged_corpus(self.paths.initial_corpus)
            self._unmerged_corpus_object_keys = keys

        except RemoteFileLookupError:
            if must_exist:
                raise
            self._logger.warning("Unmerged corpus not found. Assume first launch")
            self._unmerged_corpus_object_keys = []


    def _delete_unmerged_corpus(self):
        keys = self._unmerged_corpus_object_keys
        if len(keys) > 0:
            self.transfer.delete_unmerged_corpus(keys)


    async def run_fuzz(
        self,
        config: FuzzerConfig,
    ):
        measure = TimeMeasure()

        try:
            with measure.measuring():
                self.status = await fuzzing.run(
                    config=config,
                    paths=self.paths,
                    settings=self._settings,
                    container_mgr=self._container_mgr,
                )

            self.crashes.extend(
                await crash.process_crashes(
                    config=config,
                    paths=self.paths,
                    settings=self._settings,
                    container_mgr=self._container_mgr,
                )
            )
        finally:
            self.fuzz_statistics = fuzzing.parse_statistics(
                measure=measure,
                paths=self.paths,
            )

    
    async def run_merge(
        self,
        config: FuzzerConfig,
    ):
        self.status = await merge.run(
            config=config,
            paths=self.paths,
            settings=self._settings,
            container_mgr=self._container_mgr,
        )


class AgentModeFuzzing(AgentModeBase):

    """Fuzzing mode implementation"""

    def __init__(
        self,
        run_id: str,
        settings: AppSettings,
        container_mgr: UserContainerManager,
        object_storage: ObjectStorage,
    ):
        super().__init__(run_id, settings, container_mgr, object_storage, "fuzzing")


    async def run(self) -> None:

        self._download_config()
        self._download_binaries()
        self._download_merged_corpus()
        chmod_recursive(file_perms=0o666, dir_perms=0o777)

        config = FuzzerConfig.load(
            config_path=self.paths.config,
            paths=self.paths,
            settings=self._settings,
        )

        self._logger.info("Starting fuzz...")
        await self.run_fuzz(config)
        if self.status.code != E_SUCCESS:
            self._logger.error("Fuzz failed")


    async def finish(self) -> None:
        try:
            self.transfer.upload_unmerged_corpus(self.run_id, self.paths.result_corpus)
        
        except:
            self._logger.exception("Unhandled exception while uploading results")


class AgentModeMerge(AgentModeBase):

    """Merge mode implementation"""

    def __init__(
        self,
        run_id: str,
        settings: AppSettings,
        container_mgr: UserContainerManager,
        object_storage: ObjectStorage,
    ):
        super().__init__(run_id, settings, container_mgr, object_storage, "merge")


    async def run(self) -> None:

        self._download_config()
        self._download_binaries()
        self._download_merged_corpus()
        self._download_unmerged_corpus()
        chmod_recursive(file_perms=0o666, dir_perms=0o777)

        config = FuzzerConfig.load(
            config_path=self.paths.config,
            paths=self.paths,
            settings=self._settings,
        )

        self._logger.info("Starting merge...")
        await self.run_merge(config)
        if self.status.code != E_SUCCESS:
            self._logger.error("Merge failed")


    async def finish(self) -> None:
        try:
            # upload only if merge completed
            if self.status.code == E_SUCCESS:
                cleanup_afl_dir(self.paths.merged_corpus)
                self.transfer.upload_merged_corpus(self.paths.merged_corpus)
                self._delete_unmerged_corpus()
        
        except:
            self._logger.exception("Unhandled exception while uploading results")


class AgentModeFirstRun(AgentModeBase):

    """FirstRun mode implementation"""

    def __init__(
        self,
        run_id: str,
        settings: AppSettings,
        container_mgr: UserContainerManager,
        object_storage: ObjectStorage,
    ):
        super().__init__(run_id, settings, container_mgr, object_storage, "firstrun")


    async def run(self) -> None:

        self._download_config()
        self._download_binaries()
        self._download_merged_corpus(must_exist=False)
        self._download_unmerged_corpus(must_exist=False)
        self._download_seeds()
        chmod_recursive(file_perms=0o666, dir_perms=0o777)

        config = FuzzerConfig.load(
            config_path=self.paths.config,
            paths=self.paths,
            settings=self._settings,
        )

        #
        # Override settings to meet first-run criterias
        #
        # TODO:
        num_iters_fr = self._settings.fuzzer.num_iterations_firstrun
        time_limit_fr = self._settings.fuzzer.time_limit_firstrun

        self._settings.fuzzer.num_iterations = num_iters_fr
        self._settings.fuzzer.time_limit = time_limit_fr

        #
        # Run in fuzzing mode.
        # If no errors encountered, run merge mode
        #

        self._logger.info("Part 1: fuzzing...")
        await self.run_fuzz(config)
        if self.status.code != E_SUCCESS:
            self._logger.error("Part 1: fuzzing - failed")
            return


        # copy new corpus files to input corpus directory
        cleanup_afl_dir(self.paths.result_corpus)
        for new_corp in os.listdir(self.paths.result_corpus):
            with suppress(shutil.SameFileError):
                shutil.copyfile(
                    src=os.path.join(self.paths.result_corpus, new_corp),
                    dst=os.path.join(self.paths.initial_corpus, new_corp),
                )
            # deleted with afl_out

        shutil.rmtree(self.paths.afl_out)
        # TODO: delete LPaths.fuzzer_log ?

        #
        # Run in merge mode.
        # Return results combined with fuzzing results
        #

        self._logger.info("Part 2: merge...")
        await self.run_merge(config)
        if self.status.code != E_SUCCESS:
            self._logger.error("Part 2: merge - failed")
            return

        self._logger.info("Firstrun completed")


    async def finish(self) -> None:
        try:
            # upload only if all checks completed
            if self.status.code == E_SUCCESS:
                self.transfer.upload_merged_corpus(self.paths.merged_corpus)
                self._delete_unmerged_corpus()
            else:
                self.fuzz_statistics = None
                self.crashes.clear()
        
        except:
            self._logger.exception("Unhandled exception while uploading results")


class AflAgent(Agent):
    def select_mode(
        self,
        settings: AppSettings,
        container_mgr: UserContainerManager,
        object_storage: ObjectStorage,
        run_id: str,
    ):
        if settings.agent.mode == FuzzerMode.fuzzing:
            return AgentModeFuzzing(run_id, settings, container_mgr, object_storage)
        if settings.agent.mode == FuzzerMode.merge:
            return AgentModeMerge(run_id, settings, container_mgr, object_storage)
        if settings.agent.mode == FuzzerMode.firstrun:
            return AgentModeFirstRun(run_id, settings, container_mgr, object_storage)

        raise ValueError(f"Invalid agent mode: '{settings.agent.mode}'")
    