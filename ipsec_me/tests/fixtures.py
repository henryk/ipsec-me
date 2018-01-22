# -*- coding: utf-8 -*-
# ipsec-me (c) Henryk Plötz

from ..models import Role, User, VPNServer


def typical_workflow():
    "create some example objects"

    Role.add_default_roles()

    u = User.register(
        email="guest@example.com",
        password="guest",
        roles=["User"],
    )

    User.register(
        email="admin@example.com",
        password="axw",
        roles=["Admin"],
    )

    v = VPNServer.create(
        name="VPN CA 1",
        external_hostname="vpn.example.com"
    )

    v.add_user(u)
