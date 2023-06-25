import logging
import os

from base_agent.utils import make_executable
from base_agent.output import Status
from base_agent.errors import AgentError, FuzzerLaunchError
from base_agent.settings import AppSettings
from base_agent.kubernetes import UserContainerManager

from .config import FuzzerConfig
from .paths import AflPaths
from .utils import (
    error_status,
    ok_status,
    prepare_merge_run,
)

async def run(
    config: FuzzerConfig,
    settings: AppSettings,
    paths: AflPaths,
    container_mgr: UserContainerManager,
) -> Status:

    #
    # Prepare everything to run fuzzer:
    #   - download files from s3
    #   - read config, prepare env, cmd
    #   - base_agent..
    #

    logger = logging.getLogger("merge")
    logger.info("Prepare everything to run merger")

    #
    # Firstrun: old_corpus, new_corpus -> corpus_merged
    # Merge: old_corpus, corpus_unmerged -> corpus_merged
    #

    cmd, env = prepare_merge_run(
        paths=paths,
        config=config,
        settings=settings,
    )

    #
    # Run fuzzer with all builtin monitors
    # Ram will be tracked via afl options too, but monitor need to report metrics
    #

    logger.info("Run merger")

    if not os.path.exists(config.target.path):
        raise FuzzerLaunchError(f"Target not found: {config.target.path}")
    make_executable(config.target.path)

    try:
        exit_code = await container_mgr.exec_command(
            cmd=cmd,
            env=env,
            cwd=paths.user_home,
            stdin_file=None,
            stdout_file=None,
            stderr_file=paths.merge_log,
            time_limit=settings.fuzzer.time_limit,
        )

        logger.info("Merger finished running. Checking status")

        #
        # Merge command must succeed
        # Otherwise, investigate an error reason
        # If merge mode interrupted, discard results
        #

        if exit_code != 0:
            msg = "Failed to launch merger"
            raise FuzzerLaunchError(f"{msg}, exit_code={exit_code}")

        status = ok_status()

    except AgentError as e:
        status = error_status(e, paths.merge_log)

    assert status is not None, "Should not happen!"

    logger.info("Exit with status code %s", status.code)

    return status
