import re, sys, os
sys.path.insert(0, '.')
from agent_security.input_shield import _ASSIGNMENT_PATTERN, SecretVault

line = 'another_token = "sameSecret999999999999"'
matches = list(re.finditer(_ASSIGNMENT_PATTERN, line))
print("Matches:", matches)

vault = SecretVault()
result = vault.mask(line)
print("masked:", repr(result))
print("count:", vault.count)
