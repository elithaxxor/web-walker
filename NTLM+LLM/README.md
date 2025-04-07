# Basic analysis
python webwalker.py example.com

# With certificate info
python webwalker.py https://example.com --show-cert

# With LLM analysis (requires transformers)
python webwalker.py https://example.com --enable-llm
