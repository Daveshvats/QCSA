# Sample Rego policy — no secrets in logs
# Place in policies/ directory of your repo
# This policy fires when a log/print statement contains references to secrets or PII.

package stca

deny[msg] {
  file := input.files[_]
  line := file.added_lines[_]
  contains(lower(line), "password")
  contains(lower(line), "print")
  msg := sprintf("Policy violation: password referenced in print statement in %s", [file.path])
}

deny[msg] {
  file := input.files[_]
  line := file.added_lines[_]
  contains(lower(line), "card_number")
  contains(lower(line), "print")
  msg := sprintf("Policy violation: card_number in print statement in %s (PCI DSS)", [file.path])
}

deny[msg] {
  file := input.files[_]
  line := file.added_lines[_]
  contains(lower(line), "secret")
  contains(lower(line), "logger")
  msg := sprintf("Policy violation: secret referenced in logger statement in %s", [file.path])
}

deny[msg] {
  file := input.files[_]
  line := file.added_lines[_]
  contains(line, "eval(")
  msg := sprintf("Policy violation: eval() is forbidden in %s — use a safe parser", [file.path])
}
