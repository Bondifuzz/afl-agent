# afl-agent

Agent implementation for afl fuzzing engine

## Deployment

1. Download repository:
```
git clone https://github.com/Bondifuzz/afl-agent.git
cd afl-agent
```

2. Build image

```bash
docker build -t afl-agent .
```

3. Run container

```bash
docker run --rm -it --name=afl-agent --env-file=.env afl-agent bash
```

## Local development

### Install and run

Using python 3.7+

```bash
git clone https://github.com/Bondifuzz/afl-agent.git
cd afl-agent

pip3 install -r requirements-dev.txt

ln -s local/dotenv .env
ln -s local/docker-compose.yml docker-compose.yml
docker-compose -p afl_agent up -d

python3 -m agent
```

### Run tests

1. Unit tests

```bash
pip3 install -r requirements-test.txt
python3 -m pytest -vv ./agent/tests/unit
```

2. Integration (functional) tests

```bash
pip3 install -r requirements-test.txt
python3 -m pytest -vv ./agent/tests/integration
```