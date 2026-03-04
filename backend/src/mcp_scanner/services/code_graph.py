"""Code Graph — AST-based behavioral analysis of MCP server source code.

Builds a graph of functions, imports, and call sites using tree-sitter,
then identifies tool handlers and categorizes dangerous/network/file operations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript
import tree_sitter_typescript as tstypescript
import tree_sitter_go as tsgo
from tree_sitter import Language, Parser, Node

logger = logging.getLogger(__name__)

# Pre-built languages
PY_LANGUAGE = Language(tspython.language())
JS_LANGUAGE = Language(tsjavascript.language())
TS_LANGUAGE = Language(tstypescript.language_typescript())
GO_LANGUAGE = Language(tsgo.language())

# Directories and files to skip
_SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
              ".tox", ".mypy_cache", ".ruff_cache", "dist", "build", ".eggs"}
_MAX_FILE_SIZE = 500_000  # 500KB


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class FunctionNode:
    name: str
    file_path: str
    line: int
    end_line: int
    parameters: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    docstring: str | None = None
    is_tool_handler: bool = False
    body_text: str = ""


@dataclass
class ImportNode:
    module: str
    names: list[str] = field(default_factory=list)
    file_path: str = ""
    line: int = 0


@dataclass
class CallSite:
    callee: str
    file_path: str
    line: int
    parent_function: str | None = None
    arguments_text: str = ""


@dataclass
class CodeGraph:
    functions: list[FunctionNode] = field(default_factory=list)
    imports: list[ImportNode] = field(default_factory=list)
    call_sites: list[CallSite] = field(default_factory=list)
    tool_handlers: list[FunctionNode] = field(default_factory=list)

    @property
    def dangerous_calls(self) -> list[CallSite]:
        """Calls to subprocess, os.system, eval, exec, etc."""
        dangerous = {
            "subprocess.run", "subprocess.call", "subprocess.Popen",
            "subprocess.check_output", "subprocess.check_call",
            "os.system", "os.popen", "os.exec", "os.execvp",
            "eval", "exec",
            "child_process.exec", "child_process.execSync",
            "child_process.spawn", "child_process.execFile",
            "exec.Command",
        }
        return [c for c in self.call_sites if c.callee in dangerous]

    @property
    def network_calls(self) -> list[CallSite]:
        """Calls to HTTP client libraries."""
        network = {
            "requests.get", "requests.post", "requests.put", "requests.delete",
            "requests.patch", "requests.request",
            "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
            "httpx.AsyncClient", "httpx.Client",
            "fetch", "axios.get", "axios.post", "axios.put", "axios.delete",
            "aiohttp.ClientSession",
            "http.Get", "http.Post", "http.NewRequest",
            "urllib.request.urlopen",
        }
        return [c for c in self.call_sites if c.callee in network]

    @property
    def file_access_calls(self) -> list[CallSite]:
        """Calls to file I/O operations."""
        file_ops = {
            "open", "pathlib.Path.read_text", "pathlib.Path.write_text",
            "pathlib.Path.read_bytes", "pathlib.Path.write_bytes",
            "shutil.copy", "shutil.move", "shutil.rmtree",
            "os.remove", "os.rename", "os.makedirs",
            "fs.readFile", "fs.readFileSync", "fs.writeFile", "fs.writeFileSync",
            "os.ReadFile", "os.WriteFile", "os.Open", "os.Create",
        }
        return [c for c in self.call_sites if c.callee in file_ops]

    def to_summary_dict(self) -> dict:
        """Serialize to a JSON-friendly dict for storage in scan result."""
        return {
            "functions": [
                {
                    "name": f.name,
                    "file": f.file_path,
                    "line": f.line,
                    "params": f.parameters,
                    "is_tool_handler": f.is_tool_handler,
                    "docstring": f.docstring,
                    "body_text": f.body_text[:3000],
                }
                for f in self.functions
            ],
            "imports": [
                {"module": i.module, "names": i.names, "file": i.file_path}
                for i in self.imports
            ],
            "call_sites": [
                {
                    "callee": c.callee,
                    "file": c.file_path,
                    "line": c.line,
                    "parent": c.parent_function,
                    "args": c.arguments_text[:200],
                }
                for c in self.call_sites
            ],
            "tool_handlers": [h.name for h in self.tool_handlers],
            "stats": {
                "total_functions": len(self.functions),
                "total_imports": len(self.imports),
                "total_call_sites": len(self.call_sites),
                "tool_handlers": len(self.tool_handlers),
                "dangerous_calls": len(self.dangerous_calls),
                "network_calls": len(self.network_calls),
                "file_access_calls": len(self.file_access_calls),
            },
        }


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

# MCP tool handler decorator / registration patterns
_PYTHON_TOOL_DECORATORS = {"tool", "server.tool", "mcp.tool", "app.tool"}
_JS_TOOL_PATTERNS = {"server.tool", "registerTool", "addTool", "server.setRequestHandler"}
_GO_TOOL_PATTERNS = {"RegisterTool", "AddTool", "HandleTool"}


class CodeGraphBuilder:
    """Parse source files and build a CodeGraph."""

    def build_from_directory(self, root_dir: Path) -> CodeGraph:
        graph = CodeGraph()
        root = Path(root_dir)

        for file_path in self._iter_files(root):
            try:
                content = file_path.read_text(errors="replace")
                rel_path = str(file_path.relative_to(root))

                suffix = file_path.suffix
                if suffix == ".py":
                    self._extract_python(content, rel_path, graph)
                elif suffix in (".js", ".mjs", ".cjs"):
                    self._extract_js_ts(content, rel_path, graph, JS_LANGUAGE)
                elif suffix in (".ts", ".tsx"):
                    self._extract_js_ts(content, rel_path, graph, TS_LANGUAGE)
                elif suffix == ".go":
                    self._extract_go(content, rel_path, graph)
            except Exception as exc:
                logger.debug("Skipping %s: %s", file_path, exc)

        self._identify_tool_handlers(graph)
        return graph

    def _iter_files(self, root: Path):
        """Walk directory, skipping excluded dirs and large files."""
        for item in root.iterdir():
            if item.name in _SKIP_DIRS:
                continue
            if item.is_dir():
                yield from self._iter_files(item)
            elif item.is_file() and item.stat().st_size <= _MAX_FILE_SIZE:
                if item.suffix in (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".go"):
                    yield item

    # --- Python extraction ---

    def _extract_python(self, source: str, file_path: str, graph: CodeGraph) -> None:
        parser = Parser(PY_LANGUAGE)
        tree = parser.parse(source.encode())
        self._walk_python(tree.root_node, source, file_path, graph, parent_func=None)

    def _walk_python(
        self, node: Node, source: str, file_path: str, graph: CodeGraph, parent_func: str | None
    ) -> None:
        if node.type in ("function_definition", "async_function_definition"):  # noqa: SIM102
            func = self._extract_python_function(node, source, file_path)
            if func:
                graph.functions.append(func)
                # Walk children with this function as parent
                for child in node.children:
                    self._walk_python(child, source, file_path, graph, func.name)
                return

        if node.type == "import_statement":
            imp = self._extract_python_import(node, source, file_path)
            if imp:
                graph.imports.append(imp)
        elif node.type == "import_from_statement":
            imp = self._extract_python_from_import(node, source, file_path)
            if imp:
                graph.imports.append(imp)
        elif node.type == "call":
            call = self._extract_python_call(node, source, file_path, parent_func)
            if call:
                graph.call_sites.append(call)

        for child in node.children:
            self._walk_python(child, source, file_path, graph, parent_func)

    def _extract_python_function(self, node: Node, source: str, file_path: str) -> FunctionNode | None:
        name_node = node.child_by_field_name("name")
        if not name_node:
            return None

        name = name_node.text.decode()
        params = []
        params_node = node.child_by_field_name("parameters")
        if params_node:
            for child in params_node.children:
                if child.type == "identifier":
                    param_name = child.text.decode()
                elif child.type == "typed_parameter":
                    # typed_parameter: name: type
                    name_child = child.children[0] if child.children else None
                    param_name = name_child.text.decode() if name_child else None
                elif child.type == "default_parameter":
                    # default_parameter: name = value OR name: type = value
                    name_child = child.child_by_field_name("name")
                    if name_child:
                        param_name = name_child.text.decode()
                    elif child.children:
                        param_name = child.children[0].text.decode()
                    else:
                        param_name = None
                elif child.type == "typed_default_parameter":
                    name_child = child.child_by_field_name("name")
                    param_name = name_child.text.decode() if name_child else None
                else:
                    continue
                if param_name and param_name not in ("self", "cls"):
                    params.append(param_name)

        # Extract decorators
        decorators = []
        if node.parent and node.parent.type == "decorated_definition":
            for child in node.parent.children:
                if child.type == "decorator":
                    dec_text = child.text.decode().lstrip("@").strip()
                    decorators.append(dec_text)

        # Extract docstring
        docstring = None
        body = node.child_by_field_name("body")
        if body and body.children:
            first = body.children[0]
            if first.type == "expression_statement" and first.children:
                expr = first.children[0]
                if expr.type == "string":
                    docstring = expr.text.decode().strip("'\"")

        body_text = node.text.decode() if node.text else ""

        return FunctionNode(
            name=name,
            file_path=file_path,
            line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            parameters=params,
            decorators=decorators,
            docstring=docstring,
            body_text=body_text,
        )

    def _extract_python_import(self, node: Node, source: str, file_path: str) -> ImportNode | None:
        text = node.text.decode()
        parts = text.replace("import ", "").strip().split(",")
        names = [p.strip().split(" as ")[0] for p in parts]
        module = names[0] if names else ""
        return ImportNode(module=module, names=names, file_path=file_path, line=node.start_point[0] + 1)

    def _extract_python_from_import(self, node: Node, source: str, file_path: str) -> ImportNode | None:
        module_node = node.child_by_field_name("module_name")
        module = module_node.text.decode() if module_node else ""
        names = []
        for child in node.children:
            if child.type == "dotted_name" and child != module_node:
                names.append(child.text.decode())
            elif child.type == "aliased_import":
                name_node = child.child_by_field_name("name")
                if name_node:
                    names.append(name_node.text.decode())
        return ImportNode(module=module, names=names, file_path=file_path, line=node.start_point[0] + 1)

    def _extract_python_call(
        self, node: Node, source: str, file_path: str, parent_func: str | None
    ) -> CallSite | None:
        func_node = node.child_by_field_name("function")
        if not func_node:
            return None
        callee = func_node.text.decode()

        args_node = node.child_by_field_name("arguments")
        args_text = args_node.text.decode() if args_node else ""

        return CallSite(
            callee=callee,
            file_path=file_path,
            line=node.start_point[0] + 1,
            parent_function=parent_func,
            arguments_text=args_text,
        )

    # --- JS/TS extraction ---

    def _extract_js_ts(self, source: str, file_path: str, graph: CodeGraph, language: Language) -> None:
        parser = Parser(language)
        tree = parser.parse(source.encode())
        self._walk_js(tree.root_node, source, file_path, graph, parent_func=None)

    def _walk_js(
        self, node: Node, source: str, file_path: str, graph: CodeGraph, parent_func: str | None
    ) -> None:
        if node.type in ("function_declaration", "method_definition", "arrow_function"):
            func = self._extract_js_function(node, source, file_path)
            if func:
                graph.functions.append(func)
                for child in node.children:
                    self._walk_js(child, source, file_path, graph, func.name)
                return

        if node.type == "import_statement":
            imp = self._extract_js_import(node, source, file_path)
            if imp:
                graph.imports.append(imp)
        elif node.type == "call_expression":
            call = self._extract_js_call(node, source, file_path, parent_func)
            if call:
                graph.call_sites.append(call)

        for child in node.children:
            self._walk_js(child, source, file_path, graph, parent_func)

    def _extract_js_function(self, node: Node, source: str, file_path: str) -> FunctionNode | None:
        name = None
        if node.type == "function_declaration":
            name_node = node.child_by_field_name("name")
            if name_node:
                name = name_node.text.decode()
        elif node.type == "method_definition":
            name_node = node.child_by_field_name("name")
            if name_node:
                name = name_node.text.decode()
        elif node.type == "arrow_function":
            # Try to get name from variable declaration parent
            if node.parent and node.parent.type == "variable_declarator":
                name_node = node.parent.child_by_field_name("name")
                if name_node:
                    name = name_node.text.decode()
            if not name:
                name = "<arrow>"

        if not name:
            return None

        params = []
        params_node = node.child_by_field_name("parameters") or node.child_by_field_name("parameter")
        if params_node:
            for child in params_node.children:
                if child.type in ("identifier", "required_parameter", "optional_parameter"):
                    p = child.text.decode().rstrip("?").split(":")[0].strip()
                    params.append(p)

        return FunctionNode(
            name=name,
            file_path=file_path,
            line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            parameters=params,
            body_text=node.text.decode() if node.text else "",
        )

    def _extract_js_import(self, node: Node, source: str, file_path: str) -> ImportNode | None:
        text = node.text.decode()
        # Extract module from 'from "module"' or 'import "module"'
        source_node = node.child_by_field_name("source")
        module = source_node.text.decode().strip("'\"") if source_node else text
        names = []
        for child in node.children:
            if child.type == "import_clause":
                for subchild in child.children:
                    if subchild.type == "identifier":
                        names.append(subchild.text.decode())
                    elif subchild.type == "named_imports":
                        for imp in subchild.children:
                            if imp.type == "import_specifier":
                                name_node = imp.child_by_field_name("name")
                                if name_node:
                                    names.append(name_node.text.decode())
        return ImportNode(module=module, names=names, file_path=file_path, line=node.start_point[0] + 1)

    def _extract_js_call(
        self, node: Node, source: str, file_path: str, parent_func: str | None
    ) -> CallSite | None:
        func_node = node.child_by_field_name("function")
        if not func_node:
            return None
        callee = func_node.text.decode()
        args_node = node.child_by_field_name("arguments")
        args_text = args_node.text.decode() if args_node else ""
        return CallSite(
            callee=callee,
            file_path=file_path,
            line=node.start_point[0] + 1,
            parent_function=parent_func,
            arguments_text=args_text,
        )

    # --- Go extraction ---

    def _extract_go(self, source: str, file_path: str, graph: CodeGraph) -> None:
        parser = Parser(GO_LANGUAGE)
        tree = parser.parse(source.encode())
        self._walk_go(tree.root_node, source, file_path, graph, parent_func=None)

    def _walk_go(
        self, node: Node, source: str, file_path: str, graph: CodeGraph, parent_func: str | None
    ) -> None:
        if node.type in ("function_declaration", "method_declaration"):
            func = self._extract_go_function(node, source, file_path)
            if func:
                graph.functions.append(func)
                for child in node.children:
                    self._walk_go(child, source, file_path, graph, func.name)
                return

        if node.type == "import_declaration":
            imps = self._extract_go_imports(node, source, file_path)
            graph.imports.extend(imps)
        elif node.type == "call_expression":
            call = self._extract_go_call(node, source, file_path, parent_func)
            if call:
                graph.call_sites.append(call)

        for child in node.children:
            self._walk_go(child, source, file_path, graph, parent_func)

    def _extract_go_function(self, node: Node, source: str, file_path: str) -> FunctionNode | None:
        name_node = node.child_by_field_name("name")
        if not name_node:
            return None
        name = name_node.text.decode()
        params = []
        params_node = node.child_by_field_name("parameters")
        if params_node:
            for child in params_node.children:
                if child.type == "parameter_declaration":
                    name_child = child.child_by_field_name("name")
                    if name_child:
                        params.append(name_child.text.decode())
        return FunctionNode(
            name=name,
            file_path=file_path,
            line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            parameters=params,
            body_text=node.text.decode() if node.text else "",
        )

    def _extract_go_imports(self, node: Node, source: str, file_path: str) -> list[ImportNode]:
        results = []
        for child in node.children:
            if child.type == "import_spec":
                path_node = child.child_by_field_name("path")
                if path_node:
                    module = path_node.text.decode().strip('"')
                    results.append(ImportNode(
                        module=module, names=[], file_path=file_path,
                        line=child.start_point[0] + 1,
                    ))
            elif child.type == "import_spec_list":
                for spec in child.children:
                    if spec.type == "import_spec":
                        path_node = spec.child_by_field_name("path")
                        if path_node:
                            module = path_node.text.decode().strip('"')
                            results.append(ImportNode(
                                module=module, names=[], file_path=file_path,
                                line=spec.start_point[0] + 1,
                            ))
        return results

    def _extract_go_call(
        self, node: Node, source: str, file_path: str, parent_func: str | None
    ) -> CallSite | None:
        func_node = node.child_by_field_name("function")
        if not func_node:
            return None
        callee = func_node.text.decode()
        args_node = node.child_by_field_name("arguments")
        args_text = args_node.text.decode() if args_node else ""
        return CallSite(
            callee=callee,
            file_path=file_path,
            line=node.start_point[0] + 1,
            parent_function=parent_func,
            arguments_text=args_text,
        )

    # --- Tool handler identification ---

    def _identify_tool_handlers(self, graph: CodeGraph) -> None:
        """Mark functions that are MCP tool handlers."""
        for func in graph.functions:
            # Python: check decorators
            for dec in func.decorators:
                dec_base = dec.split("(")[0].strip()
                if dec_base in _PYTHON_TOOL_DECORATORS:
                    func.is_tool_handler = True
                    break

            # JS/TS/Go: check if function is registered as a tool via call sites
            if not func.is_tool_handler:
                for call in graph.call_sites:
                    if call.callee in _JS_TOOL_PATTERNS or call.callee in _GO_TOOL_PATTERNS:
                        # Check if the function name appears in the arguments
                        if func.name in call.arguments_text:
                            func.is_tool_handler = True
                            break

        graph.tool_handlers = [f for f in graph.functions if f.is_tool_handler]
