Key Features & How It Is Better

The engine has been substantially rebuilt from a simple pattern-matcher into a robust data-flow analyzer.

    Configuration-Driven Rule Engine

        What's Added: Vulnerability rules, sinks, and taint sources are now defined in an external sast_config.json file rather than hardcoded in Python.

        Why it's Better: You can instantly add support for new vulnerability classes (like SSRF or Path Traversal) or new web frameworks without modifying the underlying AST parser.

    Source-to-Sink Taint Tracking

        What's Added: The scanner traces variables from known untrusted sources (e.g., request, sys.argv) and evaluates how they mutate across concatenations, f-strings, % formatting, and .format() calls.

        Why it's Better: It drastically reduces false positives. Safe hardcoded queries (e.g., db.execute("SELECT * FROM users")) are ignored, while obfuscated payloads are correctly flagged.

    Cycle-Safe Scope Resolution

        What's Added: Replaces hardcoded recursion depth limits with a visited node-set tracking system and local-scope mapping.

        Why it's Better: The engine can track deep variable reassignments (a = b, b = c, c = request) endlessly without triggering infinite recursion or crashing the pipeline.

    Dual-Mode Sink Matching

        What's Added: Supports a standard strict-match mode and an optional --aggressive heuristic mode.

        Why it's Better: Strict mode eliminates noise for clean CI/CD or LLM ingestion. Aggressive mode uses substring matching to catch zero-days, dynamic dispatch (getattr), and wrapper functions (e.g., run_system_cmd()).

    Pipeline-Native Auto-Resolution

        What's Added: The script uses __file__ to dynamically calculate target paths.

        Why it's Better: You can execute python3 tools/sast_scanner.py from anywhere in the project, and it will automatically locate the target_app and sast_config.json files.

Configuration (sast_config.json)

Rules are constructed by defining taint_sources and vulnerability blocks.

    sinks: The functions that execute the payload (e.g., execute, Popen).

    regex: Optional structural validation to reduce English-language false positives (e.g., ensuring a SQL payload actually starts with SELECT, INSERT, etc.).


# Standard pipeline run (Text output, strict matching)
python3 tools/sast_scanner.py

# Machine-readable output for LLM or CI/CD integration
python3 tools/sast_scanner.py --format json

# SARIF format for GitHub Advanced Security / GitLab integration
python3 tools/sast_scanner.py --format sarif

# Aggressive heuristic mode (Highest recall, useful for rigorous testing)
python3 tools/sast_scanner.py --aggressive