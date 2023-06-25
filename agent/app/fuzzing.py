from typing import Dict
import logging
import os

from base_agent.utils import TimeMeasure, make_executable
from base_agent.output import Status
from base_agent.errors import AgentError, FuzzerLaunchError
from base_agent.settings import AppSettings
from base_agent.kubernetes import UserContainerManager

from .config import FuzzerConfig
from .paths import *
from .utils import (
    AFLFuzzStatistics,
    prepare_fuzz_run,
    null_statistics_fuzz,
    error_status,
    ok_status,
)


def parse_statistics(paths: AflPaths, measure: TimeMeasure) -> AFLFuzzStatistics:
    
    if not os.path.isfile(paths.fuzzer_stats):
        return null_statistics_fuzz(measure)


    raw_stats: Dict[str, str] = {}
    with open(paths.fuzzer_stats, "r") as stats_fd:
        for stats_line in stats_fd:
            tmp = stats_line.split(':', 1)
            if len(tmp) != 2:
                continue
            raw_stats[tmp[0].strip()] = tmp[1].strip()

    stats_convert = {
        'paths_total': 'corpus_count',
        'paths_favored': 'corpus_favored',
        'paths_found': 'corpus_found',
        'paths_imported': 'corpus_imported',
        'variable_paths': 'corpus_variable',
        'cur_path': 'cur_item',
        'unique_crashes': 'saved_crashes',
        'unique_hangs': 'saved_hangs',
    }

    # convert to new format
    for s_old in stats_convert:
        if s_old in raw_stats:
            s_new = stats_convert[s_old]
            raw_stats[s_new] = raw_stats[s_old]
            del raw_stats[s_old]

    # convert 100% to 1.0
    raw_stats['stability'] = float(raw_stats["stability"][:-1]) / 100
    raw_stats['bitmap_cvg'] = float(raw_stats["bitmap_cvg"][:-1]) / 100

    raw_stats.pop("start_time", None)
    raw_stats.pop("finish_time", None)

    return AFLFuzzStatistics(
        work_time=int(measure.elapsed.total_seconds()),
        **raw_stats
    )


async def run(
    config: FuzzerConfig,
    settings: AppSettings,
    paths: AflPaths,
    container_mgr: UserContainerManager,
) -> Status:

    #
    # Prepare everything to run fuzzer:
    #   - read config, prepare env, cmd
    #   - find target binary
    #   - ...
    #

    logger = logging.getLogger("fuzzing")
    logger.info("Prepare everything to run fuzzer")

    cmd, env = prepare_fuzz_run(
        paths=paths,
        config=config,
        settings=settings,
    )

    #
    # Run fuzzer with builtin disk monitor
    # Ram and run time will be tracked via afl options
    #

    logger.info("Run fuzzer")

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
            stderr_file=paths.fuzzer_log,
            time_limit=settings.fuzzer.time_limit,
        )


        logger.info("Fuzzer finished running. Checking status")

        if exit_code != 0:
            msg = "Fuzzer exited with error"
            raise FuzzerLaunchError(f"{msg}, exit_code={exit_code}")

        status = ok_status()

    except AgentError as e:
        status = error_status(e, paths.fuzzer_log)

    assert status is not None, "Should not happen!"

    logger.info("Exit with status code %s", status.code)

    return status
