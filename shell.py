import importlib
import traceback
import typing

# most part of the code are derived from Django


def repl_ipython(locals_: typing.Dict[str, typing.Any]):
    from IPython import start_ipython  # type: ignore

    start_ipython(argv=[], user_ns=locals_)


def repl_bpython(locals_: typing.Dict[str, typing.Any]):
    import bpython  # type: ignore

    bpython.embed(locals=locals_)


def repl_ptpython(locals_: typing.Dict[str, typing.Any]):
    from ptpython.repl import embed  # type: ignore

    return embed(locals=locals_)


def repl_python(locals_: typing.Dict[str, typing.Any]):
    import code
    import os

    # Set up a dictionary to serve as the environment for the shell, so
    # that tab completion works on objects that are imported at runtime.
    locals_ = locals_.copy()
    try:  # Try activating rlcompleter, because it's handy.
        import readline
    except ImportError:
        pass
    else:
        # We don't have to wrap the following import in a 'try', because
        # we already know 'readline' was imported successfully.
        import rlcompleter

        readline.set_completer(rlcompleter.Completer(locals_).complete)
        # Enable tab completion on systems using libedit (e.g. macOS).
        # These lines are copied from Python's Lib/site.py.
        readline_doc = getattr(readline, "__doc__", "")
        if readline_doc is not None and "libedit" in readline_doc:
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab:complete")

    # We want to honor both $PYTHONSTARTUP and .pythonrc.py, so follow system
    # conventions and get $PYTHONSTARTUP first then .pythonrc.py.
    for pythonrc in [
        os.environ.get("PYTHONSTARTUP"),
        os.path.expanduser("~/.pythonrc.py"),
    ]:
        if not pythonrc:
            continue
        if not os.path.isfile(pythonrc):
            continue
        with open(pythonrc) as handle:
            pythonrc_code = handle.read()
        # Match the behavior of the cpython shell where an error in
        # PYTHONSTARTUP prints an exception and continues.
        try:
            exec(compile(pythonrc_code, pythonrc, "exec"), locals_)
        except Exception:
            traceback.print_exc()

    code.interact(local=locals_)


repls = {
    "ipython": repl_ipython,
    "bpython": repl_bpython,
    "ptpython": repl_ptpython,
    "python": repl_python,
}


precedence = ["ptpython", "bpython", "ipython", "python"]


imported_modules = [
    "cognito_emulator.userpool.models",
]


def main():
    import cognito_emulator.userpool.asgi  # noqa: F401
    from cognito_emulator.db import registry, session, session_factory

    registry.set(session_factory())

    modules = [importlib.import_module(mod_name) for mod_name in imported_modules]

    locals_ = {}
    for mod in modules:
        locals_.update((k, getattr(mod, k)) for k in dir(mod) if not k.startswith("__"))

    locals_["session"] = session

    try:
        for type_ in precedence:
            try:
                repls[type_](locals_=locals_)
                break
            except ImportError:
                continue
    finally:
        session.remove()


if __name__ == "__main__":
    main()
