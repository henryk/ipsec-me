#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ipsec-me (c) Henryk Plötz

import sys
import traceback
sys.path.insert(0, '.')

from flask_script import Manager, Shell, Server
from flask_migrate import Migrate, MigrateCommand, upgrade
import alembic
import alembic.config
from ipsec_me import create_app, db
from ipsec_me.models import User, Role, VPNServer, UserType

app = create_app()
migrate = Migrate(app, db, directory="ipsec_me/migrations")


def _make_context():
    return {
        "app": app,
        "db": db,
    }

manager = Manager(app)
manager.add_command("shell", Shell(make_context=_make_context))
manager.add_command("runserver", Server(port=app.config['PORT']))
manager.add_command("publicserver", Server(port=app.config['PORT'], host="0.0.0.0"))
manager.add_command('db', MigrateCommand)


@manager.option('-e', '--email', help='email address', required=True)
@manager.option('-p', '--password', help='password', required=True)
@manager.option('-a', '--admin', help='make user an admin user', action='store_true', default=None)
def user_add(email, password, admin=False):
    "add a user to the database"
    if admin:
        roles = ["Admin"]
    else:
        roles = ["User"]
    User.register(
        email=email,
        password=password,
        confirmed=True,
        roles=roles
    )


@manager.option('-e', '--email', help='email address', required=True)
def user_del(email):
    "delete a user from the database"
    obj = User.find(email=email)
    if obj:
        obj.delete()
        print("Deleted")
    else:
        print("User not found")

@manager.option('-n', '--name', help='VPN name', required=True)
@manager.option('-h', '--hostname', help='VPN server hostname', required=True)
@manager.option('-u', '--user', help='VPN user', required=False, nargs='*')
@manager.option('-a', '--admin-user', help='VPN admin user', required=False, nargs='*')
@manager.option('-b', '--base-dn', help='VPN CA base DN', required=False, default="")
def vpn_create(name, hostname, user, admin_user, base_dn):
    "Create a VPN"
    v = VPNServer.create(name=name, external_hostname=hostname, CA_params={'base_dn': base_dn})
    for email in user:
        u = User.find(email=email)
        v.add_user(u, user_type=UserType.USER)
    for email in admin_user:
        u = User.find(email=email)
        v.add_user(u, user_type=UserType.ADMIN)
    print("Created")


@manager.command
def drop_db():
    "drop all databases, instantiate schemas"
    db.reflect()
    db.drop_all()


@manager.option('-m', '--migration',
    help='create database from migrations',
    action='store_true', default=None)
def init_db(migration):
    "drop all databases, instantiate schemas"
    db.drop_all()

    if migration:
        # create database using migrations
        print("applying migration")
        upgrade()
    else:
        # create database from model schema directly
        db.create_all()
        db.session.commit()
        cfg = alembic.config.Config("ipsec_me/migrations/alembic.ini")
        alembic.command.stamp(cfg, "head")
    Role.add_default_roles()


if __name__ == "__main__":
    manager.run()
