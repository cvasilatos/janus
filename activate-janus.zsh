source .venv/bin/activate

completion_dir="$PWD/completions"
fpath=("$completion_dir" $fpath)

if ! typeset -f compdef >/dev/null 2>&1; then
  autoload -Uz compinit
  compinit
fi

autoload -Uz _janus
compdef _janus janus
