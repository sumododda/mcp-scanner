"""Tests for the Code Graph builder and data structures."""

import pytest
from pathlib import Path
import tempfile
import textwrap

from mcp_scanner.services.code_graph import CodeGraphBuilder, CodeGraph


@pytest.fixture
def builder():
    return CodeGraphBuilder()


def _write_file(root: Path, relpath: str, content: str) -> Path:
    fp = root / relpath
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(textwrap.dedent(content))
    return fp


class TestPythonParsing:
    def test_extracts_functions(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root, "server.py", """\
                import os

                def hello(name: str):
                    \"\"\"Say hello.\"\"\"
                    print(name)

                async def fetch_data(url):
                    pass
            """)
            graph = builder.build_from_directory(root)
            names = [f.name for f in graph.functions]
            assert "hello" in names
            assert "fetch_data" in names

    def test_extracts_imports(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root, "server.py", """\
                import os
                from pathlib import Path
                import subprocess
            """)
            graph = builder.build_from_directory(root)
            modules = [i.module for i in graph.imports]
            assert "os" in modules
            assert "pathlib" in modules
            assert "subprocess" in modules

    def test_extracts_call_sites(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root, "server.py", """\
                import subprocess

                def run_cmd(cmd):
                    subprocess.run(cmd, shell=True)
                    os.system("ls")
            """)
            graph = builder.build_from_directory(root)
            callees = [c.callee for c in graph.call_sites]
            assert "subprocess.run" in callees
            assert "os.system" in callees

    def test_call_site_parent_function(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root, "server.py", """\
                def do_thing():
                    print("hello")
            """)
            graph = builder.build_from_directory(root)
            print_calls = [c for c in graph.call_sites if c.callee == "print"]
            assert len(print_calls) >= 1
            assert print_calls[0].parent_function == "do_thing"

    def test_function_parameters(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root, "server.py", """\
                def process(name: str, count: int = 5):
                    pass
            """)
            graph = builder.build_from_directory(root)
            func = next(f for f in graph.functions if f.name == "process")
            assert "name" in func.parameters
            assert "count" in func.parameters

    def test_function_decorators(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root, "server.py", """\
                from mcp import server

                @server.tool()
                def my_tool():
                    pass
            """)
            graph = builder.build_from_directory(root)
            func = next(f for f in graph.functions if f.name == "my_tool")
            assert any("server.tool" in d for d in func.decorators)


class TestToolHandlerIdentification:
    def test_python_decorator_tool_handler(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root, "server.py", """\
                from mcp import Server

                server = Server("test")

                @server.tool()
                def read_file(path: str):
                    \"\"\"Read a file from disk.\"\"\"
                    return open(path).read()
            """)
            graph = builder.build_from_directory(root)
            assert len(graph.tool_handlers) >= 1
            handler_names = [h.name for h in graph.tool_handlers]
            assert "read_file" in handler_names

    def test_non_tool_function_not_marked(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root, "server.py", """\
                def helper():
                    pass
            """)
            graph = builder.build_from_directory(root)
            assert len(graph.tool_handlers) == 0


class TestDerivedProperties:
    def test_dangerous_calls(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root, "server.py", """\
                import subprocess
                import os

                def run(cmd):
                    subprocess.run(cmd)
                    os.system(cmd)
                    eval(cmd)
            """)
            graph = builder.build_from_directory(root)
            dangerous = graph.dangerous_calls
            callees = {c.callee for c in dangerous}
            assert "subprocess.run" in callees
            assert "os.system" in callees
            assert "eval" in callees

    def test_network_calls(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root, "server.py", """\
                import requests

                def fetch():
                    requests.get("https://example.com")
                    requests.post("https://example.com/data")
            """)
            graph = builder.build_from_directory(root)
            network = graph.network_calls
            callees = {c.callee for c in network}
            assert "requests.get" in callees
            assert "requests.post" in callees

    def test_file_access_calls(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root, "server.py", """\
                def read():
                    f = open("test.txt")
                    data = f.read()
            """)
            graph = builder.build_from_directory(root)
            file_calls = graph.file_access_calls
            assert any(c.callee == "open" for c in file_calls)


class TestCodeGraphSerialization:
    def test_to_summary_dict(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root, "server.py", """\
                import os

                def hello():
                    print("hi")
            """)
            graph = builder.build_from_directory(root)
            summary = graph.to_summary_dict()
            assert "functions" in summary
            assert "imports" in summary
            assert "call_sites" in summary
            assert "stats" in summary
            assert summary["stats"]["total_functions"] >= 1


class TestSkipPatterns:
    def test_skips_git_directory(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root, ".git/config.py", """\
                secret = "password123"
            """)
            _write_file(root, "main.py", """\
                def main():
                    pass
            """)
            graph = builder.build_from_directory(root)
            files = {f.file_path for f in graph.functions}
            assert not any(".git" in f for f in files)

    def test_skips_node_modules(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root, "node_modules/pkg/index.js", """\
                function test() {}
            """)
            _write_file(root, "main.py", """\
                def main():
                    pass
            """)
            graph = builder.build_from_directory(root)
            files = {f.file_path for f in graph.functions}
            assert not any("node_modules" in f for f in files)

    def test_skips_large_files(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Create a file larger than 500KB
            large = root / "big.py"
            large.write_text("x = 1\n" * 100_000)
            _write_file(root, "small.py", """\
                def small():
                    pass
            """)
            graph = builder.build_from_directory(root)
            files = {f.file_path for f in graph.functions}
            assert "big.py" not in files


class TestJavaScriptParsing:
    def test_extracts_js_functions(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root, "server.js", """\
                function handleRequest(req, res) {
                    console.log("hello");
                }

                const fetchData = (url) => {
                    return fetch(url);
                };
            """)
            graph = builder.build_from_directory(root)
            names = [f.name for f in graph.functions]
            assert "handleRequest" in names

    def test_extracts_js_imports(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root, "server.mjs", """\
                import express from "express";
                import { readFile } from "fs";
            """)
            graph = builder.build_from_directory(root)
            modules = [i.module for i in graph.imports]
            assert "express" in modules
            assert "fs" in modules


class TestGoParsing:
    def test_extracts_go_functions(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root, "main.go", """\
                package main

                import "fmt"

                func main() {
                    fmt.Println("hello")
                }

                func handleTool(name string) {
                    fmt.Println(name)
                }
            """)
            graph = builder.build_from_directory(root)
            names = [f.name for f in graph.functions]
            assert "main" in names
            assert "handleTool" in names

    def test_extracts_go_imports(self, builder):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root, "main.go", """\
                package main

                import (
                    "fmt"
                    "os"
                )

                func main() {}
            """)
            graph = builder.build_from_directory(root)
            modules = [i.module for i in graph.imports]
            assert "fmt" in modules
            assert "os" in modules
