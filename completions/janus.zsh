#compdef janus

_janus() {
  eval $(env _TYPER_COMPLETE_ARGS="${words[1,$CURRENT]}" _JANUS_COMPLETE=complete_zsh janus)
}

compdef _janus janus
