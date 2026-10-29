"""
self_healing.py - Autonomous Syntax Error Recovery Guard
=========================================================
Catches Python syntax and indentation errors before AST parsing.
Autonomously diagnoses line errors and applies rule-based patches:
  1. Missing colons (def, if, elif, else, for, while, try, except, class, with)
  2. Missing block indentation after compound statement headers
  3. Single '=' assignment used in 'if' or 'elif' condition
  4. Unclosed parentheses, brackets, or braces
  5. Unclosed string literals
"""

import ast
import re
from typing import Dict, List, Tuple

# ── Pillar 3B: Input Limits & Safe Parsing ────────────────────────────────────
try:
    from agent_security.input_limits import check_source, safe_parse, InputRejected
    _LIMITS_AVAILABLE = True
except ImportError:
    _LIMITS_AVAILABLE = False
    safe_parse = ast.parse

try:
    from agent_security.nesting_guard import check_nesting_depth
    _NESTING_GUARD_AVAILABLE = True
except ImportError:
    _NESTING_GUARD_AVAILABLE = False
# ─────────────────────────────────────────────────────────────────────────────


class SelfHealingAgent:
    """
    Autonomous code repair agent that detects and heals syntax/indentation errors.
    """

    BLOCK_KEYWORDS = (
        'def', 'class', 'if', 'elif', 'else', 'for', 'while',
        'try', 'except', 'finally', 'with', 'async def', 'async for', 'async with'
    )

    def __init__(self, max_passes: int = 6):
        self.max_passes = max_passes

    def heal(self, source_code: str) -> Dict:
        """
        Inspects source code for syntax validity.
        If invalid, attempts multi-pass autonomous repairs.
        """
        if not source_code or not source_code.strip():
            return {
                'status': 'empty',
                'is_healed': False,
                'clean_code': source_code,
                'repairs': [],
                'repair_details': [],
                'errors_diagnosed': []
            }

        # ── Pillar 3B/3C: input limits check before any regex / repair pass ───
        if _LIMITS_AVAILABLE:
            is_safe, reason = check_source(source_code)
            if not is_safe:
                err_type = 'NestingTooDeep' if 'Bracket nesting depth' in reason else 'InputRejected'
                return {
                    'status': 'blocked',
                    'is_healed': False,
                    'clean_code': source_code,
                    'repairs': [],
                    'repair_details': [],
                    'errors_diagnosed': [{
                        'type': err_type,
                        'message': reason,
                        'line': 0,
                        'offset': 0,
                        'text': '',
                    }],
                }
        elif _NESTING_GUARD_AVAILABLE:
            is_safe, depth = check_nesting_depth(source_code)
            if not is_safe:
                return {
                    'status': 'blocked',
                    'is_healed': False,
                    'clean_code': source_code,
                    'repairs': [],
                    'repair_details': [],
                    'errors_diagnosed': [{
                        'type': 'NestingTooDeep',
                        'message': f'Nesting depth {depth} exceeds safety limit (Pillar 3)',
                        'line': 0,
                        'offset': 0,
                        'text': '',
                    }],
                }
        # ─────────────────────────────────────────────────────────────────────

        # 1. Check if code is already valid
        try:
            safe_parse(source_code)
            return {
                'status': 'valid',
                'is_healed': False,
                'clean_code': source_code,
                'repairs': [],
                'repair_details': [],
                'errors_diagnosed': []
            }
        except (SyntaxError, IndentationError) as initial_err:
            first_error_diag = self._format_error(initial_err)

        current_code = source_code
        all_repairs = []
        all_details = []
        diagnosed_errors = [first_error_diag]

        for pass_idx in range(self.max_passes):
            try:
                safe_parse(current_code)
                # Success! Code is now valid
                return {
                    'status': 'healed',
                    'is_healed': True,
                    'clean_code': current_code,
                    'repairs': all_repairs,
                    'repair_details': all_details,
                    'errors_diagnosed': diagnosed_errors
                }
            except (SyntaxError, IndentationError) as err:
                err_info = self._format_error(err)
                if err_info not in diagnosed_errors:
                    diagnosed_errors.append(err_info)

                # Attempt targeted healing on current error
                patched_code, repairs_made, details_made = self._apply_healing_pass(current_code, err)
                if not repairs_made or patched_code == current_code:
                    # Try general normalization pass
                    patched_code, repairs_made, details_made = self._apply_general_cleanup(current_code)
                    if not repairs_made or patched_code == current_code:
                        break

                all_repairs.extend(repairs_made)
                all_details.extend(details_made)
                current_code = patched_code

        # Final verification
        try:
            safe_parse(current_code)
            return {
                'status': 'healed',
                'is_healed': True,
                'clean_code': current_code,
                'repairs': all_repairs,
                'repair_details': all_details,
                'errors_diagnosed': diagnosed_errors
            }
        except (SyntaxError, IndentationError) as final_err:
            return {
                'status': 'unresolved',
                'is_healed': False,
                'clean_code': current_code,
                'repairs': all_repairs,
                'repair_details': all_details,
                'errors_diagnosed': diagnosed_errors,
                'final_error': str(final_err)
            }

    @staticmethod
    def _make_detail(line_num: int, rule: str, description: str, before: str, after: str, action: str = "") -> Dict:
        return {
            'line': line_num,
            'rule': rule,
            'description': description,
            'before': before,
            'after': after,
            'action': action or description,
        }

    def _apply_healing_pass(self, code: str, err: Exception) -> Tuple[str, List[str], List[Dict]]:
        lines = code.splitlines()
        repairs = []
        details = []
        line_num = getattr(err, 'lineno', None)

        if line_num is not None and 1 <= line_num <= len(lines):
            idx = line_num - 1
            target_line = lines[idx]

            # 1. Missing Colon check
            healed_line, repaired = self._fix_missing_colon(target_line)
            if repaired:
                lines[idx] = healed_line
                repairs.append(f"Line {line_num}: Added missing colon ':' after block statement.")
                details.append(self._make_detail(
                    line_num=line_num,
                    rule="SYN-001: Missing Colon",
                    description="Added missing colon ':' after block statement.",
                    before=target_line,
                    after=healed_line,
                    action="Appended ':' to block header"
                ))
                return "\n".join(lines), repairs, details

            # Also check previous line if current is IndentationError
            if isinstance(err, IndentationError) and idx > 0:
                prev_line = lines[idx - 1]
                prev_healed, prev_rep = self._fix_missing_colon(prev_line)
                if prev_rep:
                    lines[idx - 1] = prev_healed
                    repairs.append(f"Line {line_num - 1}: Added missing colon ':' before indented block.")
                    details.append(self._make_detail(
                        line_num=line_num - 1,
                        rule="SYN-001: Missing Colon",
                        description="Added missing colon ':' before indented block.",
                        before=prev_line,
                        after=prev_healed,
                        action="Appended ':' to block header"
                    ))
                    return "\n".join(lines), repairs, details

            # 2. Align elif/else/except/finally with matching header
            if target_line.strip().startswith(('elif', 'else', 'except', 'finally')):
                for prev_i in range(idx - 1, -1, -1):
                    prev_l = lines[prev_i]
                    if prev_l.strip().startswith(('if ', 'if(', 'elif ', 'try:', 'try ')):
                        matched_indent = len(prev_l) - len(prev_l.lstrip())
                        new_line = (' ' * matched_indent) + target_line.strip()
                        if new_line != target_line:
                            lines[idx] = new_line
                            repairs.append(f"Line {line_num}: Aligned '{target_line.strip()}' with outer block header.")
                            details.append(self._make_detail(
                                line_num=line_num,
                                rule="SYN-002: Block Alignment",
                                description=f"Aligned '{target_line.strip()}' with outer block header.",
                                before=target_line,
                                after=new_line,
                                action="Adjusted indentation to match outer header"
                            ))
                            return "\n".join(lines), repairs, details

            # 3. Missing Indentation after block statement
            if idx > 0 and self._is_block_header(lines[idx - 1]):
                if not target_line.startswith(('    ', '\t')) and target_line.strip():
                    parent_indent = len(lines[idx - 1]) - len(lines[idx - 1].lstrip())
                    new_indented = (' ' * (parent_indent + 4)) + target_line.lstrip()
                    lines[idx] = new_indented
                    repairs.append(f"Line {line_num}: Applied indentation for statement following '{lines[idx - 1].strip()}'.")
                    details.append(self._make_detail(
                        line_num=line_num,
                        rule="SYN-003: Indentation Defect",
                        description=f"Applied indentation for statement following '{lines[idx - 1].strip()}'.",
                        before=target_line,
                        after=new_indented,
                        action="Added 4-space block indentation"
                    ))
                    return "\n".join(lines), repairs, details

            # 4. Accidental single '=' in if/elif
            healed_eq, eq_rep = self._fix_assignment_in_conditional(target_line)
            if eq_rep:
                lines[idx] = healed_eq
                repairs.append(f"Line {line_num}: Replaced assignment '=' with equality comparison '=='.")
                details.append(self._make_detail(
                    line_num=line_num,
                    rule="SYN-004: Assignment in Conditional",
                    description="Replaced assignment '=' with equality comparison '=='.",
                    before=target_line,
                    after=healed_eq,
                    action="Replaced '=' with '=='"
                ))
                return "\n".join(lines), repairs, details

            # 5. Unclosed quotes on line
            healed_quotes, q_rep = self._fix_unclosed_quotes(target_line)
            if q_rep:
                lines[idx] = healed_quotes
                repairs.append(f"Line {line_num}: Closed unterminated string literal.")
                details.append(self._make_detail(
                    line_num=line_num,
                    rule="SYN-005: Unclosed String",
                    description="Closed unterminated string literal.",
                    before=target_line,
                    after=healed_quotes,
                    action="Appended matching quote"
                ))
                return "\n".join(lines), repairs, details

        # 5. Global unmatched brackets check
        healed_brackets, b_rep = self._fix_unmatched_brackets(code)
        if b_rep:
            repairs.append(b_rep)
            details.append(self._make_detail(
                line_num=len(lines),
                rule="SYN-006: Unclosed Delimiters",
                description=b_rep,
                before=code.rstrip(),
                after=healed_brackets.rstrip(),
                action="Appended closing delimiter(s)"
            ))
            return healed_brackets, repairs, details

        return code, [], []

    def _apply_general_cleanup(self, code: str) -> Tuple[str, List[str], List[Dict]]:
        lines = code.splitlines()
        repairs = []
        details = []
        modified = False

        # Pass 1: Ensure all block headers have colons
        for i, line in enumerate(lines):
            healed, rep = self._fix_missing_colon(line)
            if rep:
                orig = lines[i]
                lines[i] = healed
                repairs.append(f"Line {i + 1}: Added missing colon ':'.")
                details.append(self._make_detail(
                    line_num=i + 1,
                    rule="SYN-001: Missing Colon",
                    description="Added missing colon ':'.",
                    before=orig,
                    after=healed,
                    action="Appended ':' to block header"
                ))
                modified = True

        # Pass 2: Progressive block indentation healing
        expected_indent = 0
        for i in range(len(lines)):
            line = lines[i]
            stripped = line.strip()
            if not stripped:
                continue

            current_indent = len(line) - len(line.lstrip())

            # If inside an active block expecting higher indent
            if expected_indent > 0 and current_indent < expected_indent:
                # Unless it's an elif/else/except/finally that matches outer indent
                is_dedent_keyword = stripped.startswith(('elif ', 'else', 'except', 'finally'))
                if is_dedent_keyword and current_indent == expected_indent - 4:
                    pass  # Legit dedent keyword
                else:
                    orig = lines[i]
                    new_indented = (' ' * expected_indent) + stripped
                    lines[i] = new_indented
                    repairs.append(f"Line {i + 1}: Adjusted block indentation.")
                    details.append(self._make_detail(
                        line_num=i + 1,
                        rule="SYN-003: Indentation Defect",
                        description="Adjusted block indentation.",
                        before=orig,
                        after=new_indented,
                        action="Aligned indentation to block scope"
                    ))
                    modified = True

            # If current line is a block header, next non-empty lines expect more indent
            if self._is_block_header(lines[i]):
                header_indent = len(lines[i]) - len(lines[i].lstrip())
                expected_indent = header_indent + 4

        if modified:
            return "\n".join(lines), repairs, details

        # Bracket check
        healed_brackets, b_rep = self._fix_unmatched_brackets(code)
        if b_rep:
            details.append(self._make_detail(
                line_num=len(lines),
                rule="SYN-006: Unclosed Delimiters",
                description=b_rep,
                before=code.rstrip(),
                after=healed_brackets.rstrip(),
                action="Appended closing delimiter(s)"
            ))
            return healed_brackets, [b_rep], details

        return code, [], []

    def _is_block_header(self, line: str) -> bool:
        s = line.strip()
        for kw in self.BLOCK_KEYWORDS:
            if s.startswith(kw + ' ') or s == kw or s == kw + ':':
                return True
        return False

    def _fix_missing_colon(self, line: str) -> Tuple[str, bool]:
        s = line.strip()
        if not s or s.endswith(':'):
            return line, False

        # Match def, class, if, elif, else, for, while, try, except, finally, with
        pattern = r'^(\s*(?:def\b|class\b|if\b|elif\b|else\b|for\b|while\b|try\b|except\b|finally\b|with\b)[^#]*)$'
        m = re.match(pattern, line)
        if m:
            # Check there isn't a trailing comment
            code_part = line.split('#')[0].rstrip()
            comment_part = (' #' + line.split('#', 1)[1]) if '#' in line else ''
            if not code_part.endswith(':'):
                return code_part + ':' + comment_part, True

        return line, False

    def _fix_assignment_in_conditional(self, line: str) -> Tuple[str, bool]:
        # Match 'if a = 5:' or 'if x = y'
        if re.search(r'\b(if|elif)\s+[^=!<>]=[^=]', line):
            patched = re.sub(r'(\b(?:if|elif)\s+[^=!<>]+)=([^=])', r'\1==\2', line, count=1)
            return patched, True
        return line, False

    def _fix_unclosed_quotes(self, line: str) -> Tuple[str, bool]:
        # Count non-escaped single and double quotes
        stripped = re.sub(r'\\.', '', line)
        single_count = stripped.count("'")
        double_count = stripped.count('"')

        if single_count % 2 != 0:
            return line + "'", True
        if double_count % 2 != 0:
            return line + '"', True
        return line, False

    def _fix_unmatched_brackets(self, code: str) -> Tuple[str, str]:
        # Strip string literals and comments to count brackets accurately
        clean = re.sub(r'#[^\n]*', '', code)
        clean = re.sub(r'("""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"[^"\n]*"|\'[^\'\n]*\')', '', clean)

        open_parens = clean.count('(') - clean.count(')')
        open_brackets = clean.count('[') - clean.count(']')
        open_braces = clean.count('{') - clean.count('}')

        additions = []
        if open_parens > 0:
            additions.append(')' * open_parens)
        if open_brackets > 0:
            additions.append(']' * open_brackets)
        if open_braces > 0:
            additions.append('}' * open_braces)

        if additions:
            closing_chars = "".join(reversed(additions))
            repaired_code = code.rstrip() + closing_chars + "\n"
            return repaired_code, f"Closed unmatched brackets/parentheses: '{closing_chars}'"

        return code, ""

    def _format_error(self, err: Exception) -> Dict:
        return {
            'type': type(err).__name__,
            'message': getattr(err, 'msg', str(err)),
            'line': getattr(err, 'lineno', 1),
            'offset': getattr(err, 'offset', 0),
            'text': getattr(err, 'text', '').strip() if getattr(err, 'text', '') else ''
        }


def heal_code(source_code: str) -> Dict:
    """Convenience function to run self-healing agent."""
    agent = SelfHealingAgent()
    return agent.heal(source_code)


if __name__ == "__main__":
    # Test cases with deliberate syntax typos
    broken_code1 = """def add_numbers(a, b)
    return a + b
"""
    broken_code2 = """def calculate(price):
if price > 100:
    return price * 0.9
else
    return price
"""
    broken_code3 = """def greet(name):
    print("Hello " + name
"""

    for idx, c in enumerate([broken_code1, broken_code2, broken_code3], 1):
        res = heal_code(c)
        print(f"\n--- Test {idx} ---")
        print("Status:", res['status'])
        print("Is Healed:", res['is_healed'])
        print("Repairs:", res['repairs'])
        print("Healed Code:\n" + res['clean_code'])
