from logging.config import dictConfig
import yaml

from base_agent.entry import agent_entry
from .app.agent import AflAgent


if __name__ == "__main__":

    with open("logging.yaml") as f:
        dictConfig(yaml.safe_load(f))

    agent_entry(AflAgent())
