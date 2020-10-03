import typing

import click
from sqlalchemy.orm import exc as orm_exc

from cognito_emulator.db import registry, session, session_factory
from cognito_emulator.userpool.models import Client, User, UserPool
from cognito_emulator.utils import generate_key


@click.group()
def cli():
    pass


@cli.command()
@click.option("--name", prompt="pool name")
def addpool(name: str):
    if session.query(session.query(UserPool).filter_by(name=name).exists()).scalar():
        raise click.BadParameter(f"pool {name} already exists")

    pool = UserPool(
        name=name,
    )
    session.add(pool)
    session.commit()
    click.echo(f"Added user pool {name}.")


def pool(ctx, param, value):
    try:
        return session.query(UserPool).filter_by(name=value).one()
    except orm_exc.NoResultFound:
        raise click.BadParameter(f"no such pool named {value}")


@cli.command()
@click.option("--pool", required=True, callback=pool)
@click.option("--email", prompt="email")
@click.option("--name")
@click.option(
    "--password", prompt="password", hide_input=True, confirmation_prompt=True
)
def adduser(pool: UserPool, email: str, name: typing.Optional[str], password: str):
    from cognito_emulator.userpool.asgi import app

    user = User(
        pool=pool,
        email=email,
        name=name if name is not None else email,
        password=app.state.kdf.hash(password),
    )

    session.add(user)
    session.commit()
    click.echo(f"Added user {name} ({email}).")


@cli.command()
@click.option("--pool", required=True, callback=pool)
@click.option("--name", required=True)
@click.option("--client-id")
@click.option("--client-secret")
@click.option("--no-client-secret", is_flag=True)
@click.option("--redirect-uri", required=True, multiple=True)
def addclient(
    pool: UserPool,
    name: str,
    client_id: typing.Optional[str],
    client_secret: typing.Optional[str],
    no_client_secret: bool,
):
    import cognito_emulator.userpool.asgi  # noqa: F401

    if client_id is None:
        client_id = generate_key(26)

    if client_secret is None and not no_client_secret:
        client_secret = generate_key(51)

    client = Client(
        pool=pool,
        name=name,
        oauth2_client_id=client_id,
        oauth2_client_secret=client_secret,
    )

    session.add(client)
    session.commit()
    click.echo(
        f"Added client {name} (client_id={client_id}, client_secret={client_secret})."
    )


def main():
    import cognito_emulator.userpool.asgi  # noqa: F401

    registry.set(session_factory())
    cli()


if __name__ == "__main__":
    main()
