import pathlib

from sqlalchemyseeder import ResolvingSeeder  # type: ignore

from cognito_emulator.db import registry, session, session_factory


def main():
    # this triggers the application initialization
    import cognito_emulator.userpool.asgi  # noqa: F401

    # import models
    import cognito_emulator.userpool.models  # noqa: F401

    registry.set(session_factory())

    seeder = ResolvingSeeder(session)

    for p in (pathlib.Path(__file__).parent / "seeds").glob("**/*.yaml"):
        print(f"reading {p}...")
        seeder.load_entities_from_yaml_string(p.read_bytes())

    session.commit()


if __name__ == "__main__":
    main()
