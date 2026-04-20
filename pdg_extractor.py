import ast

class PDGExtractor(ast.NodeVisitor):
    def __init__(self):
        # We will store dependencies as a list of strings to feed the NLP model
        self.nodes = []
        self.control_edges = []
        self.data_edges = []
        
        # Track state during traversal
        self.current_control_node = "root"
        self.var_definitions = {}  # var_name -> defining_node_id
        self.node_counter = 0

    def add_node(self, desc):
        node_id = f"N{self.node_counter}"
        self.node_counter += 1
        self.nodes.append(f"{node_id}: {desc}")
        return node_id

    def add_control_edge(self, target_id, source_id):
        self.control_edges.append(f"{target_id} depends on {source_id} (Control)")

    def add_data_edge(self, target_id, var_name, source_id):
        self.data_edges.append(f"{target_id} uses '{var_name}' from {source_id} (Data)")

    def visit_FunctionDef(self, node):
        node_id = self.add_node(f"Function {node.name}")
        self.control_edges.append(f"{node_id} depends on root (Control)")
        
        # Record arguments as data sources
        for arg in node.args.args:
            self.var_definitions[arg.arg] = node_id
            
        prev_control = self.current_control_node
        self.current_control_node = node_id
        
        self.generic_visit(node)
        
        self.current_control_node = prev_control

    def visit_Assign(self, node):
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        val_str = ast.unparse(node.value) if hasattr(ast, 'unparse') else "value"
        
        node_id = self.add_node(f"Assign {', '.join(targets)} = {val_str}")
        self.add_control_edge(node_id, self.current_control_node)
        
        # Find data dependencies (variables used on the right side)
        for var_node in ast.walk(node.value):
            if isinstance(var_node, ast.Name) and isinstance(var_node.ctx, ast.Load):
                if var_node.id in self.var_definitions:
                    self.add_data_edge(node_id, var_node.id, self.var_definitions[var_node.id])
        
        # Update data definitions
        for target in targets:
            self.var_definitions[target] = node_id

    def visit_If(self, node):
        test_str = ast.unparse(node.test) if hasattr(ast, 'unparse') else "condition"
        node_id = self.add_node(f"If {test_str}")
        self.add_control_edge(node_id, self.current_control_node)
        
        # Data dependencies in condition
        for var_node in ast.walk(node.test):
            if isinstance(var_node, ast.Name) and isinstance(var_node.ctx, ast.Load):
                if var_node.id in self.var_definitions:
                    self.add_data_edge(node_id, var_node.id, self.var_definitions[var_node.id])
                    
        # Visit body with IF as control node
        prev_control = self.current_control_node
        self.current_control_node = node_id
        for stmt in node.body:
            self.visit(stmt)
            
        # Visit orelse with IF as control node (we can distinguish true/false branches in a more complex PDG)
        self.current_control_node = f"{node_id}_Else"
        if node.orelse:
            for stmt in node.orelse:
                self.visit(stmt)
                
        self.current_control_node = prev_control

    def visit_Return(self, node):
        ret_str = ast.unparse(node.value) if hasattr(ast, 'unparse') and node.value else "None"
        node_id = self.add_node(f"Return {ret_str}")
        self.add_control_edge(node_id, self.current_control_node)
        
        if node.value:
            for var_node in ast.walk(node.value):
                if isinstance(var_node, ast.Name) and isinstance(var_node.ctx, ast.Load):
                    if var_node.id in self.var_definitions:
                        self.add_data_edge(node_id, var_node.id, self.var_definitions[var_node.id])

def extract_pdg_context(source_code: str) -> str:
    """
    Parses the source code to extract a simplified Program Dependence Graph (PDG),
    capturing Control Flow and Data Flow dependencies.
    """
    try:
        tree = ast.parse(source_code)
        extractor = PDGExtractor()
        extractor.visit(tree)
        
        pdg_representation = "Nodes:\n" + "\n".join(extractor.nodes) + "\n"
        pdg_representation += "Edges:\n" + "\n".join(extractor.control_edges + extractor.data_edges)
        
        # To avoid making the prompt too massive, we truncate if it's too large
        if len(pdg_representation) > 1000:
            pdg_representation = pdg_representation[:1000] + "\n...[Truncated]"
            
        return pdg_representation.strip()
    except Exception as e:
        return f"PDG parsing failed: {str(e)}"

if __name__ == "__main__":
    sample_code = '''
def calculate_discount(price, is_member):
    discount = 0
    if is_member:
        discount = price * 0.1
    final_price = price - discount
    return final_price
'''
    print(extract_pdg_context(sample_code))
