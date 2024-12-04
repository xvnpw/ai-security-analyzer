# Updating Fabric Patterns

First, let's download the latest patterns from GitHub:

```bash
bash scripts/download_fabric_patterns.sh
```

The next step is to create a `fabric_tools.txt` file that contains Python code. `generate_fabric_tools.py` uses OpenAI to create a summary from prompts, so make sure you have set the `OPENAI_API_KEY` environment variable.

```bash
python scripts/generate_fabric_tools.py
```

Open `fabric_tools.txt` and review it for any obvious errors:

```bash
code fabric_tools.txt
```

Replace the code in `fabric_tools.py` with the functions in `fabric_tools.txt`.

Run the tests:

```bash
pytest tests/test_fabric_tools.py
```

You will probably get errors, because number of patterns is changed. Adjust tests and re-run.
