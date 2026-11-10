"""Asset-inventory tool exposed to agents as a Semantic Kernel plugin."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

from semantic_kernel.functions import kernel_function


class AssetInventoryPlugin:
    def __init__(self, inventory_path: Path):
        data = json.loads(Path(inventory_path).read_text(encoding="utf-8"))
        self.hosts = {h["hostname"].upper(): h for h in data["hosts"]}
        self.identities = {i["username"].lower(): i for i in data["identities"]}
        self.cloud = data["cloud"]

    @kernel_function(name="lookup_host", description="Look up a host by hostname.")
    def lookup_host(self, hostname: Annotated[str, "Hostname"]) -> str:
        return json.dumps(self.hosts.get(hostname.upper()))

    @kernel_function(name="lookup_ip", description="Find the host that owns an IP address.")
    def lookup_ip(self, ip: Annotated[str, "IPv4 address"]) -> str:
        for h in self.hosts.values():
            if ip in h["ips"]:
                return json.dumps(h)
        return json.dumps(None)

    @kernel_function(name="lookup_user", description="Look up an identity by username or email.")
    def lookup_user(self, user: Annotated[str, "Username or email"]) -> str:
        key = user.lower().split("@")[0]
        return json.dumps(self.identities.get(key))

    @kernel_function(name="lookup_cloud", description="Find a cloud account by account id or access key id.")
    def lookup_cloud(self, identifier: Annotated[str, "Account id or access key id"]) -> str:
        for acct in self.cloud:
            if identifier == acct["account_id"]:
                return json.dumps({**acct, "matched_key_identity": None})
            for key in acct["access_keys"]:
                if identifier == key["key_id"]:
                    return json.dumps({**acct, "matched_key_identity": key["identity"]})
        return json.dumps(None)
