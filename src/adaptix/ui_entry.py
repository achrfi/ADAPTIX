"""`adaptix` — open the interactive screen, or pass arguments straight to the CLI.

The dispatch is deliberately thin: with no arguments the operator gets the screen; with
any argument the exact same argv goes to the CLI, so scripting and the previous
workflow keep working unchanged.
"""
import os
import sys


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ('ui', 'tui', 'screen'):
        from src.adaptix.ui.screen import main as ui_main
        return ui_main()
    if not argv:
        # A bare `adaptix` opens the screen. Without a TTY (a pipe, a cron job) the
        # screen cannot render, so print the CLI help instead of failing silently.
        if sys.stdout.isatty():
            from src.adaptix.ui.screen import main as ui_main
            return ui_main()
        from src.adaptix.main import build_arg_parser
        build_arg_parser().print_help()
        return 0
    from src.adaptix.main import main as cli_main
    return cli_main()


if __name__ == '__main__':
    raise SystemExit(main())
