"""Shared Z3 utilities — consolidated from counterexamples.py + multi_language_advanced.py."""
from __future__ import annotations
import ast
from typing import Any, Dict, Optional


def ast_to_z3(node: ast.AST, z3_vars: Dict[str, Any]) -> Optional[Any]:
    """Convert a Python AST expression to a Z3 formula."""
    try:
        import z3
    except ImportError:
        return None
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            args = [ast_to_z3(v, z3_vars) for v in node.values]
            args = [a for a in args if a is not None]
            return z3.And(*args) if args else None
        elif isinstance(node.op, ast.Or):
            args = [ast_to_z3(v, z3_vars) for v in node.values]
            args = [a for a in args if a is not None]
            return z3.Or(*args) if args else None
    if isinstance(node, ast.Compare):
        left = ast_to_z3(node.left, z3_vars)
        if left is None: return None
        for op, comp in zip(node.ops, node.comparators):
            right = ast_to_z3(comp, z3_vars)
            if right is None: return None
            if isinstance(op, ast.LtE): left = left <= right
            elif isinstance(op, ast.Lt): left = left < right
            elif isinstance(op, ast.GtE): left = left >= right
            elif isinstance(op, ast.Gt): left = left > right
            elif isinstance(op, ast.Eq): left = left == right
            elif isinstance(op, ast.NotEq): left = left != right
        return left
    if isinstance(node, ast.BinOp):
        left = ast_to_z3(node.left, z3_vars)
        right = ast_to_z3(node.right, z3_vars)
        if left is None or right is None: return None
        if isinstance(node.op, ast.Add): return left + right
        elif isinstance(node.op, ast.Sub): return left - right
        elif isinstance(node.op, ast.Mult): return left * right
        elif isinstance(node.op, ast.Div): return left / right
        elif isinstance(node.op, ast.Mod): return left % right
    if isinstance(node, ast.UnaryOp):
        operand = ast_to_z3(node.operand, z3_vars)
        if operand is None: return None
        if isinstance(node.op, ast.Not): return z3.Not(operand)
        elif isinstance(node.op, ast.USub): return -operand
    if isinstance(node, ast.Name):
        if node.id in z3_vars: return z3_vars[node.id]
        z3_vars[node.id] = z3.Int(node.id)
        return z3_vars[node.id]
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool): return z3.BoolVal(node.value)
        if isinstance(node.value, int): return z3.IntVal(node.value)
        if isinstance(node.value, float): return z3.RealVal(node.value)
    return None
