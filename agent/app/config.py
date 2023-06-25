from __future__ import annotations
from enum import Enum

import json
import os
from typing import List, Optional, Dict
from pydantic import BaseModel, Extra, Field, validator, ValidationError
from base_agent.settings import AppSettings

from base_agent.errors import InvalidConfigError

from .paths import AflPaths


class ConfigModel(BaseModel, extra=Extra.forbid):
    pass


class StrEnum(str, Enum):
    # make enum case insensitive
    @classmethod
    def _missing_(cls, value: str):
        for member in cls:
            if member.value.lower() == value.lower():
                return member


class AsanOptions(ConfigModel):
    abort_on_error: Optional[str]
    symbolize: Optional[str]

    quarantine_size: Optional[str]  # -
    quarantine_size_mb: Optional[str]  # -
    redzone: Optional[str]  # -
    max_redzone: Optional[str]  # -
    debug: Optional[str]  # -
    report_globals: Optional[str]  # -
    check_initialization_order: Optional[str]  # +
    replace_str: Optional[str]  # -
    replace_intrin: Optional[str]  # -
    detect_stack_use_after_return: Optional[str]  # +
    min_uar_stack_size_log: Optional[str]  # -
    max_uar_stack_size_log: Optional[str]  # -
    uar_noreserve: Optional[str]  # -
    max_malloc_fill_size: Optional[str]  # +
    malloc_fill_byte: Optional[str]  # +
    allow_user_poisoning: Optional[str]  # -
    sleep_before_dying: Optional[str]  # -
    check_malloc_usable_size: Optional[str]  # -
    unmap_shadow_on_exit: Optional[str]  # -
    protect_shadow_gap: Optional[str]  # -
    print_stats: Optional[str]  # -
    print_legend: Optional[str]  # -
    atexit: Optional[str]  # -
    print_full_thread_history: Optional[str]  # -
    poison_heap: Optional[str]  # +
    poison_partial: Optional[str]  # +
    poison_array_cookie: Optional[str]  # +
    alloc_dealloc_mismatch: Optional[str]  # +
    new_delete_type_mismatch: Optional[str]  # +
    strict_init_order: Optional[str]  # +
    strict_string_checks: Optional[str]  # +
    start_deactivated: Optional[str]  # +
    detect_invalid_pointer_pairs: Optional[str]  # +
    detect_container_overflow: Optional[str]  # +
    detect_odr_violation: Optional[str]  # +
    dump_instruction_bytes: Optional[str]  # +
    suppressions: Optional[str]  # -
    halt_on_error: Optional[str]  # -
    log_path: Optional[str]  # -
    use_odr_indicator: Optional[str]  # +
    allocator_frees_and_returns_null_on_realloc_zero: Optional[str]  # +
    verify_asan_link_order: Optional[str]  # +

    @validator(
        "quarantine_size",
        "quarantine_size_mb",
        "redzone",
        "max_redzone",
        "debug",
        "report_globals",
        "replace_str",
        "replace_intrin",
        "min_uar_stack_size_log",
        "max_uar_stack_size_log",
        "uar_noreserve",
        "allow_user_poisoning",
        "sleep_before_dying",
        "check_malloc_usable_size",
        "unmap_shadow_on_exit",
        "protect_shadow_gap",
        "print_stats",
        "print_legend",
        "atexit",
        "print_full_thread_history",
        "suppressions",
        "halt_on_error",
        "log_path",
    )
    def can_not_be_overriden(cls, value):
        if value is not None:
            raise ValueError(f"Option can not be overriden")
        return value


class AFLModes(StrEnum):
    Normal="Normal"
    QEMU="QEMU"
    Unicorn="Unicorn"
    Wine="Wine"
    Frida="Frida"
    # NonInstrumented


class AFLSchedules(StrEnum):
    all="*"
    explore="explore"
    fast="fast"
    coe="coe"
    lin="lin"
    quad="quad"
    exploit="exploit"
    mmopt="mmopt"
    rare="rare"
    seek="seek"


class AFLQueue(StrEnum):
    sequential="sequential"
    weighted="weighted"


class AFLOptions(ConfigModel):

    mode: AFLModes = Field(AFLModes.Normal)
    schedule: Optional[AFLSchedules]# = Field(AFLSchedules.fast)
    dict_path: Optional[str] = Field(None, alias="dict")
    file_extension: Optional[str] = Field(None)
    target_input: Optional[str] = Field(None) # stdin|@@|/some/path
    min_length: Optional[int] # Default: 1
    max_length: Optional[int] # Default: MAX_FILE(1 * 1024 * 1024)
    queue_selection: AFLQueue = Field(AFLQueue.weighted)

    python_module: Optional[str]
    custom_mutator_library: Optional[str]
    custom_mutator_only: bool = Field(False)

    hang_timeout: Optional[int]
    child_timeout: Optional[int]
    kill_signal: Optional[int]# = Field(9) # SIGKILL
    map_size: Optional[int]


class ConfigOptions(ConfigModel):
    afl: AFLOptions   = Field(default_factory=AFLOptions)
    asan: AsanOptions = Field(default_factory=AsanOptions)
    # TODO: msan, ...


class TargetConfig(ConfigModel):
    path: Optional[str] = Field(None)
    args: List[str]     = Field(default_factory=list)


class FuzzerConfig(ConfigModel):
    target: TargetConfig   = Field(default_factory=TargetConfig)
    env: Dict[str, str]    = Field(default_factory=dict)
    options: ConfigOptions = Field(default_factory=ConfigOptions)

    def _join_envs(self, envs: Dict[str, str], sep: str = ":"):
        return sep.join([f"{k}={v}" for k, v in envs.items()])
        # return sep.join([f"{k}={repr(v)}" for k, v in envs.items()])
        # TODO:

    def get_sanitizers_env(self) -> Dict[str, str]:
        res: Dict[str, str] = {}
        res['ASAN_OPTIONS'] = self._join_envs(
            self.options.asan.dict(by_alias=True, exclude_none=True)
        )
        # TODO: msan, ...
        return res


    def _check_config(self):
        # check sanitizers environments
        for env in ['ASAN_OPTIONS', 'MSAN_OPTIONS', 'TSAN_OPTIONS', 'UBSAN_OPTIONS']:
            if env in self.env:
                raise InvalidConfigError('Sanitizer options must be set with sanitizer configs!')

        # check afl environments
        for env in self.env.keys():
            if env.startswith("AFL_") and env != "AFL_PRELOAD":
                raise InvalidConfigError(
                    "Afl environments forbidden to manually set(except AFL_PRELOAD), please use config properties"
                )

    
    def _init(
        self, 
        paths: AflPaths,
        settings: AppSettings,
    ):
        self._check_config()

        #
        # Setup target
        # like /bondi/fuzzer/<target>
        #

        if self.target.path is None:
            self.target.path = settings.agent.default_target
        self.target.path = os.path.join(paths.user_home, self.target.path)

        #
        # Setup afl config
        #

        if self.options.afl.mode != AFLModes.Normal:
            raise InvalidConfigError(
                "Only 'Normal' mode supported!"
            )

        if self.options.afl.target_input is not None:
            target_input = self.options.afl.target_input
            if target_input.strip().lower() not in ["@@", "stdin"]:
                # TODO: tmpfs
                target_input = os.path.abspath(os.path.join(paths.user_home, target_input))
                self.options.afl.target_input = target_input
        
        #
        # Setup sanitizers
        #

        # asan
        self.options.asan.debug = "0"
        self.options.asan.abort_on_error = "1"
        self.options.asan.symbolize = "0"

        # TODO:
        # self.options.msan.exitcode = "86"
        # self.options.msan.symbolize = "0"


    @classmethod
    def load(
        cls,
        config_path: str,
        paths: AflPaths,
        settings: AppSettings,
    ):
        try:
            config_dict = {}

            if os.path.exists(config_path):
                with open(config_path, "r", encoding="utf-8") as f:
                    config_dict = json.loads(f.read())

                if not isinstance(config_dict, dict):
                    raise ValueError("Invalid format")

            config = cls(**config_dict)
            config._init(paths, settings)
            return config

        except ValidationError as e:
            raise InvalidConfigError(str(e)) from e

        except ValueError as e:
            raise InvalidConfigError(str(e)) from e
    
