from contextlib import suppress
import os
import shutil
import hashlib
from typing import Dict, List, Optional, Tuple

from base_agent.errors.codes import E_SUCCESS
from base_agent.errors import AgentError

from base_agent.settings import AppSettings, FuzzerMode
from base_agent.output import Statistics, Status
from base_agent.utils import TimeMeasure, rfc3339

from .config import AFLModes, AFLSchedules, FuzzerConfig
from .paths import *

class AFLFuzzStatistics(Statistics):
    # start_time: int # unix time indicating the start time of afl-fuzz
    # last_update: int # unix time corresponding to the last update of this file
    # run_time: int # run time in seconds to the last update of this file
    # fuzzer_pid: int # PID of the fuzzer process
    cycles_done: int # queue cycles completed so far
    cycles_wo_finds: int # number of cycles without any new paths found
    execs_done: int # number of execve() calls attempted
    execs_per_sec: float # overall number of execs per second
    # execs_ps_last_min: float # <UNDOCUMENTED>
    corpus_count: int # total number of entries in the queue
    corpus_favored: int # number of queue entries that are favored
    corpus_found: int # number of entries discovered through local fuzzing
    # corpus_imported: int # number of entries imported from other instances
    corpus_variable: int # number of test cases showing variable behavior
    # max_depth: int # number of levels in the generated data set
    # cur_item: int # currently processed entry number
    # pending_favs: int # number of favored entries still waiting to be fuzzed
    # pending_total: int # number of all entries waiting to be fuzzed
    stability: float # percentage of bitmap bytes that behave consistently
    bitmap_cvg: float # percentage of edge coverage found in the map so far
    # saved_crashes: int # number of unique crashes recorded
    # saved_hangs: int # number of unique hangs encountered
    # last_find: int # seconds since the last find was found
    # last_crash: int # seconds since the last crash was found
    # last_hang: int # seconds since the last hang was found
    # execs_since_crash: int # execs since the last crash was found
    # exec_timeout: int # the -t command line value
    slowest_exec_ms: int # real time of the slowest execution in ms
    peak_rss_mb: int # max rss usage reached during fuzzing in MB
    # cpu_affinity: int # <UNDOCUMENTED>
    # edges_found: int # how many edges have been found
    # total_edges: int # <UNDOCUMENTED>
    # var_byte_count: int # how many edges are non-deterministic
    # havoc_expansion: int # <UNDOCUMENTED>
    # auto_dict_entries: int # <UNDOCUMENTED>
    # testcache_size: int # <UNDOCUMENTED>
    # testcache_count: int # <UNDOCUMENTED>
    # testcache_evict: int # <UNDOCUMENTED>
    # afl_banner: str # banner text (e.g., the target name)
    # afl_version: str # the version of AFL++ used
    # target_mode: str # default, persistent, qemu, unicorn, non-instrumented
    # command_line: str # full command line used for the fuzzing session


def null_statistics_fuzz(measure: TimeMeasure) -> AFLFuzzStatistics:
    return AFLFuzzStatistics(
        work_time=int(measure.elapsed.total_seconds()),
        cycles_done=0,
        cycles_wo_finds=0,
        execs_done = 0,
        execs_per_sec = 0.0,
        corpus_count = 0,
        corpus_favored = 0,
        corpus_found = 0,
        corpus_variable = 0,
        stability = 0.0,
        bitmap_cvg = 0.0,
        slowest_exec_ms = 0,
        peak_rss_mb = 0,
    )


def prepare_fuzz_run(config: FuzzerConfig, settings: AppSettings, paths: AflPaths) -> Tuple[List[str], Dict[str, str]]:

    envs = {
        **config.env,
        **config.get_sanitizers_env(),
    }

    envs["AFL_NO_UI"] = "1"
    envs["AFL_DEBUG"] = "0"
    envs["AFL_BENCH_UNTIL_CRASH"] = "1"
    #envs["AFL_TARGET_ENV"] = config._join_envs(config.env, " ")

        
    args = []
    args.append("afl-fuzz")
    
    if config.options.afl.mode != AFLModes.Normal:
        args.append({
            AFLModes.QEMU:    "-Q",
            AFLModes.Unicorn: "-U",
            AFLModes.Wine:    "-W",
            AFLModes.Frida:   "-O",
        }[config.options.afl.mode])
        
    if config.options.afl.schedule is not None:
        if config.options.afl.schedule == AFLSchedules.all:
            envs["AFL_CYCLE_SCHEDULES"] = "1"
        else:
            args.append("-p")
            args.append(config.options.afl.schedule.value)

    if config.options.afl.dict_path is not None:
        args.append("-x")
        args.append(config.options.afl.dict_path)
        
    if config.options.afl.file_extension is not None:
        args.append("-e")
        args.append(config.options.afl.file_extension)

    if config.options.afl.target_input is not None:
        args.append("-f")
        args.append(config.options.afl.target_input)

    if config.options.afl.min_length is not None:
        args.append("-g")
        args.append(str(config.options.afl.min_length))
        envs["AFL_INPUT_LEN_MIN"] = str(config.options.afl.min_length)

    if config.options.afl.max_length is not None:
        args.append("-G")
        args.append(str(config.options.afl.max_length))
        envs["AFL_INPUT_LEN_MAX"] = str(config.options.afl.max_length)

        
    args.append("-V")
    if settings.agent.mode == FuzzerMode.firstrun:
        args.append(str(settings.fuzzer.time_limit_firstrun))
    else:
        args.append(str(settings.fuzzer.time_limit))

    args.append("-E")
    if settings.agent.mode == FuzzerMode.firstrun:
        args.append(str(settings.fuzzer.num_iterations_firstrun))
    else:
        args.append(str(settings.fuzzer.num_iterations))

    args.append("-i")
    args.append(paths.initial_corpus)
    if not os.path.exists(paths.initial_corpus):
        os.mkdir(paths.initial_corpus)

    # If no initial corpus given - create one
    if len(next(os.walk(paths.initial_corpus))[2]) == 0:
        with open(os.path.join(paths.initial_corpus, 'init'), 'xb') as fd:
            fd.write(b'123') # TODO: random?

    args.append("-o")
    args.append(paths.afl_out)
    if not os.path.exists(paths.afl_out):
        os.mkdir(paths.afl_out)

    args.append("--")
    args.append(config.target.path)
    args.extend(config.target.args)

    return args, envs


def prepare_repro_run(config: FuzzerConfig, settings: AppSettings, paths: AflPaths) -> Tuple[List[str], Dict[str, str]]:
    envs = {
        **config.env,
        **config.get_sanitizers_env(),
    }

    args = []
    args.append(config.target.path)
    args.extend(config.target.args)

    # prepare crash in caller(stdin/arg/file)

    return args, envs


def prepare_merge_run(config: FuzzerConfig, settings: AppSettings, paths: AflPaths) -> Tuple[List[str], Dict[str, str]]:
    
    envs = {
        **config.env,
        **config.get_sanitizers_env(),
    }

    
    args = []
    args.append("afl-cmin.bash")

    if config.options.afl.mode != AFLModes.Normal:
        args.append({
            AFLModes.QEMU:    "-Q",
            AFLModes.Unicorn: "-U",
            AFLModes.Wine:    "-W",
            AFLModes.Frida:   "-O",
        }[config.options.afl.mode])


    if config.options.afl.target_input is not None:
        args.append("-f")
        args.append(config.options.afl.target_input)


    args.append("-i")
    args.append(os.path.abspath(paths.initial_corpus))

    args.append("-o")
    args.append(os.path.abspath(paths.merged_corpus))

    # output dir should not exists
    if os.path.exists(paths.merged_corpus):
        shutil.rmtree(paths.merged_corpus)

    args.append("--")
    args.append(config.target.path)
    args.extend(config.target.args)

    return args, envs


def prepare_showmap_run(config: FuzzerConfig, settings: AppSettings) -> Tuple[List[str], Dict[str, str]]:
    
    envs = {
        **config.env,
        **config.get_sanitizers_env(),
    }
    #envs["AFL_CMIN_ALLOW_ANY"] = "1"
    
    args = []
    args.append("afl-showmap")

    if config.options.afl.mode != AFLModes.Normal:
        args.append({
            AFLModes.QEMU:    "-Q",
            AFLModes.Unicorn: "-U",
            AFLModes.Wine:    "-W",
            AFLModes.Frida:   "-O",
        }[config.options.afl.mode])

    #args.append("-m")
    #args.append(str(settings.agent.fuzzer.ram_limit)) # TODO: b/mb/...
    
    #args.append("-t")
    #args.append(...)

    args.append("-o")
    args.append(os.devnull)

    # show edge coverage only, ignore hit counts
    args.append("-e")

    # enable output format for cmin
    #args.append("-Z")
    
    #if config.options.afl.target_input is not None:
    #    args.append("-H")
    #    shutil.copy(input_path, config.options.afl.target_input)
    #    args.append(config.options.afl.target_input)
    #
    #elif "@@" in config.target.args:
    #    args.append("-H")
    #    args.append(input_path) # TODO: create copy
    

    args.append("--")
    args.append(config.target.path)
    args.extend(config.target.args)

    return args, envs


def ok_status() -> Status:
    return Status(code=E_SUCCESS, message="Success")


def error_status(e: AgentError, log_file: Optional[str]):

    if log_file is None:
        details = None
    else:
        with open(log_file, "r", encoding="utf-8") as f:
            details = f.read()

    return Status(
        code=e.code,
        message=e.message,
        details=details[-10000:],
    )


def cleanup_afl_dir(path: str):
    for f in os.scandir(path):

        if f.is_dir():
            if f.is_symlink():
                os.unlink(f.path)
            else:
                shutil.rmtree(f.path)

    with suppress(FileNotFoundError):
        os.unlink(os.path.join(path, "README.txt"))


def sha_file(file_path: str) -> str:
    sha1 = hashlib.sha1()

    with open(file_path, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            sha1.update(data)

    return sha1.hexdigest()
