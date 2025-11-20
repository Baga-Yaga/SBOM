import tree_sitter_python as tspython
import json
import tree_sitter_javascript as tsjavascript
from tree_sitter import Language, Parser
import os
import zipfile
import tempfile
import shutil
import networkx as nx
# Removed unused Flask imports (like jsonify, CORS) as this module runs in a background thread.


LANGUAGE_GRAMMAR_PARSER = {
    '.py': ('python', tspython, 'Python'),
    '.js': ('javascript', tsjavascript, 'JavaScript'),
    '.ts': ('javascript', tsjavascript, 'TypeScript')
}

parsers = {}

def load_parser(file_ext):
    """Load and cache Tree-sitter parser for the given file extension."""
    if file_ext in parsers:
        return parsers[file_ext]

    lang_info = LANGUAGE_GRAMMAR_PARSER.get(file_ext)
    if not lang_info:
        return None, None, None  

    lang_slug, grammar, lang_full_name = lang_info
    
    try:
        ts_language = Language(grammar.language())
        parser = Parser(ts_language)
        parsers[file_ext] = (parser, lang_slug, lang_full_name)
        return parser, lang_slug, lang_full_name
    except Exception as e:
        print(f"Error loading Tree-sitter parser for {file_ext}: {e}")
        return None, lang_slug, lang_full_name


def parse_code(code_bytes, language_slug, parser):
    tree = parser.parse(code_bytes)
    root_node = tree.root_node
    results = {'functions': [], 'imports': [], 'classes': []}
    
    if language_slug == 'python':
        for node in root_node.children:
            if node.type in ['import_statement', 'import_from_statement']:
                results['imports'].append(node.text.decode('utf8').strip())
    
    elif language_slug == 'javascript':
        query_str = """
            (import_statement) @import
            (function_declaration name: (identifier) @func.name)
            (lexical_declaration (variable_declarator name: (identifier) @func.name value: [(arrow_function) (function)]))
            (class_declaration name: (identifier) @class.name)
            (export_statement declaration: [
                (function_declaration name: (identifier) @func.name)
                (class_declaration name: (identifier) @class.name)
                (lexical_declaration (variable_declarator name: (identifier) @func.name value: [(arrow_function) (function)]))
            ])
            """
        
        if query_str:
            query = parser.language.query(query_str)
            captures = query.captures(root_node)
            
            processed_captures = set()
            for node, capture_name in captures:
                text = node.text.decode('utf8').strip()
                if (text, capture_name) not in processed_captures:
                    if 'import' in capture_name:
                        results['imports'].append(text)
                    processed_captures.add((text, capture_name))
    return results

def to_cytoscape_json(G):
    elements = []
    for node, attrs in G.nodes(data=True):
        elements.append({'data': {'id': node, **attrs}, 'group': 'nodes'})
    for source, target in G.edges():
        elements.append({'data': {'source': source, 'target': target}, 'group': 'edges'})
    # Return the Python list/dict structure
    return elements

def export_graph_data(zip_file_path):
    """
    Accepts the file system path (string) of the uploaded ZIP file, 
    extracts it, parses the code, and returns the Cytoscape graph data structure.
    """
    
    # Using a temporary directory for extraction
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
        except zipfile.BadZipFile:
            # FIX: Return a Python dictionary on error, not a Flask response object.
            print(f"Error: Invalid zip file at {zip_file_path}")
            return {'error': 'Invalid zip file.', 'elements': []}
        except Exception as e:
            # FIX: Return a Python dictionary on error.
            print(f"Error: Failed to process zip file {zip_file_path}: {e}")
            return {'error': f'Failed to process zip file: {e}', 'elements': []}

        # --- Graph Building Phase ---
        G = nx.Graph()
        
        # Traverse the extracted directory
        for root, _, files in os.walk(temp_dir):
            # Create a path relative to the temporary root for consistent IDs
            relative_root = os.path.relpath(root, temp_dir)
            
            for filename in files:
                file_ext = os.path.splitext(filename)[1]
                
                if file_ext in LANGUAGE_GRAMMAR_PARSER:
                    parser, lang_slug, lang_full_name = load_parser(file_ext)
                    if not parser:
                        continue

                    # Create nodes
                    file_node_id = os.path.normpath(os.path.join(relative_root, filename))
                    
                    # Add language node if not exists
                    if lang_full_name not in G:
                        G.add_node(lang_full_name, type='language', lang_slug=lang_slug, label=lang_full_name, group='language')

                    G.add_node(file_node_id, type='file', filename=filename, label=filename, group='file')
                    G.add_edge(lang_full_name, file_node_id, type='contains')
                    
                    file_path = os.path.join(root, filename)
                    try:
                        with open(file_path, 'rb') as f:
                            code_bytes = f.read()
                            analysis = parse_code(code_bytes, lang_slug, parser)
                            
                            for symbol_type, symbols in analysis.items():
                                for symbol in symbols:
                                    # Truncate long import statements for clarity
                                    if symbol_type == 'imports' and len(symbol) > 70:
                                        symbol_label = symbol[:67] + '...'
                                    else:
                                        symbol_label = symbol
                                    
                                    # Add a unique ID for the symbol based on its file context
                                    symbol_id = f"{file_node_id}::{symbol_label}"
                                    
                                    # Add symbol node
                                    if symbol_id not in G:
                                        G.add_node(symbol_id, type='symbol', label=symbol_label, symbol_type=symbol_type, group='symbol')
                                        G.add_edge(file_node_id, symbol_id, type='defines')

                    except Exception as e:
                        print(f"Could not parse file {file_path}: {e}")
    
    # Convert graph to Cytoscape format and return the Python structure
    graph_data = to_cytoscape_json(G)
    
    return graph_data