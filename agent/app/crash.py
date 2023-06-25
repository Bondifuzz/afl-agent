from __future__ import annotations
from typing import TYPE_CHECKING

import os
import re
import shutil
import logging
from base64 import b64encode
from base_agent.output import CrashBase

from agent.app.utils import prepare_showmap_run, prepare_repro_run
from base_agent.utils import make_executable

from .paths import AflPaths

from base_agent.errors import FuzzerLaunchError

if TYPE_CHECKING:
    from typing import List, Tuple
    from agent.app.config import FuzzerConfig
    from base_agent.settings import AppSettings
    from base_agent.kubernetes import UserContainerManager

class AflCrash(CrashBase):
    showmap_hash: str

def _create_crash(
    crash_path: str, 
    crash_type: str, 
    output_path: str, 
    reproduced: bool,
    showmap_hash: str,
) -> AflCrash:

    with open(crash_path, "rb") as f:
        input = b64encode(f.read()).decode()

    with open(output_path, "r", encoding="utf-8") as f:
        output = f.read()

    return AflCrash(
        input_id=None,
        type=crash_type,
        input=input,
        output=output,
        reproduced=reproduced,
        showmap_hash=showmap_hash,
    )


def _look_for_crashes(
    paths: AflPaths,
) -> List[Tuple[str, str]]:

    def find_crashes(dir: str) -> List[str]:
        res = []
        if os.path.exists(dir):
            for filename in os.listdir(dir):
                if filename.lower() != "readme.txt":
                    res.append(os.path.join(dir, filename))

        return res

    crashes = []

    for crash_path in find_crashes(paths.crashes_dir):
        crashes.append((crash_path, "crash"))

    for hang_path in find_crashes(paths.hangs_dir):
        crashes.append((hang_path, "hang"))

    return crashes


async def process_crashes(
    config: FuzzerConfig,
    settings: AppSettings,
    paths: AflPaths,
    container_mgr: UserContainerManager,
) -> List[AflCrash]:
    crashes = []
    for crash_path, crash_type in _look_for_crashes(paths):
        # TODO: exception handling in reproduce
        crashes.append(
            await _process_crash(
                paths=paths,
                config=config,
                settings=settings,
                container_mgr=container_mgr,
                crash_path=crash_path,
                crash_type=crash_type,
            )
        )
    return crashes


async def _process_crash(
    config: FuzzerConfig,
    settings: AppSettings,
    paths: AflPaths,
    container_mgr: UserContainerManager,
    crash_path: str,
    crash_type: str,
) -> AflCrash:

    logger = logging.getLogger("repro")
    logger.info(f"Running reproduce for \"{crash_path}\"")

    cmd, env = prepare_repro_run(
        paths=paths,
        config=config,
        settings=settings,
    )

    stdin_file = None
    if config.options.afl.target_input is not None:
        shutil.copyfile(
            src=crash_path,
            dst=config.options.afl.target_input,
        )
    elif "@@" in cmd:
        for i in range(len(cmd)):
            if cmd[i] == '@@':
                cmd[i] = crash_path
    else:
        stdin_file = crash_path


    if not os.path.exists(config.target.path):
        raise FuzzerLaunchError(f"Target not found: {config.target.path}")
    make_executable(config.target.path)

    exit_code = await container_mgr.exec_command(
        cmd=cmd,
        cwd=paths.user_home,
        env=env,
        stdin_file=stdin_file,
        stdout_file=paths.repro_log, # TODO: None?
        stderr_file=paths.repro_log,
        time_limit=1 * 60, # TODO:
    )

    # ProgramAbortedError or AgentError(monitors)

    reproduced = exit_code != 0

    msg = "Crash info: type=%s, reproduced=%s"
    logger.info(msg, crash_type, reproduced)

    showmap_hash = await _get_showmap_hash(
        paths=paths,
        config=config,
        settings=settings,
        container_mgr=container_mgr,
        crash_path=crash_path
    )

    return _create_crash(
        crash_path=crash_path,
        crash_type=crash_type,
        output_path=paths.repro_log,
        reproduced=reproduced,
        showmap_hash=showmap_hash,
    )


async def _get_showmap_hash(
    config: FuzzerConfig,
    settings: AppSettings,
    paths: AflPaths,
    container_mgr: UserContainerManager,
    crash_path: str,
) -> str:

    logger = logging.getLogger("repro")
    logger.info(f"Running afl-showmap for \"{crash_path}\"")

    cmd, env = prepare_showmap_run(
        config=config,
        settings=settings,
    )

    stdin_file = None
    if config.options.afl.target_input is not None:
        shutil.copyfile(
            src=crash_path,
            dst=config.options.afl.target_input,
        )
    elif cmd.count('@@') > 0:
        for i in range(len(cmd)):
            if cmd[i] == '@@':
                cmd[i] = crash_path # TODO: create copy?
    else:
        stdin_file = crash_path

    exit_code = await container_mgr.exec_command(
        cmd=cmd,
        cwd=paths.user_home,
        env=env,
        stdin_file=stdin_file,
        stdout_file=paths.showmap_log,
        stderr_file=paths.showmap_log,
        time_limit=1 * 60, # TODO:
    )

    # 0 - normal work
    # 1 - timeout or other errors
    # 2 - target crashed
    if exit_code not in [0, 2]:
        msg = f"Failed to launch afl-showmap - exit_code={exit_code}"
        raise FuzzerLaunchError(msg)
        
    reproduced = exit_code == 2
    showmap_hash = None

    with open(paths.showmap_log, "r") as f:
        hash_re = re.compile(r"Hash of coverage map: ([0-9a-fA-F]+)")
        for line in f:
            match = hash_re.search(line)
            if match is not None:
                showmap_hash: str = match.group(1)
                break
            #if "Hash of coverage map: " in line:
            #    r"Hash of coverage map: ([0-9a-fA-F]+)"
            #    showmap_hash = line.split("map: ")[1].split("\u001b")[0].strip()
            #    break

    if showmap_hash is None:
        with open(paths.showmap_log, "r") as f:
            showmap_output = f.read()
            raise FuzzerLaunchError(
                message="Failed to get hash from afl-showmap",
                details=f"Output:\n{showmap_output}",
            )

    logger.info(
        "afl-showmap completed with reproduced=%s, sha=%s",
        reproduced, showmap_hash,
    )

    return showmap_hash
