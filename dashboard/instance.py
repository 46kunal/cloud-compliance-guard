"""Which server is answering this request. Shown in the UI so the load balancer test is visible."""
import os
import socket
import urllib.request
from functools import lru_cache

IMDS = "http://169.254.169.254/latest"


def _imds(path, token):
    request = urllib.request.Request(f"{IMDS}/{path}", headers={"X-aws-ec2-metadata-token": token})
    with urllib.request.urlopen(request, timeout=1) as response:
        return response.read().decode()


@lru_cache(maxsize=1)
def instance_info() -> dict:
    """EC2 metadata via IMDSv2 when running on EC2; environment/hostname values elsewhere."""
    info = {"instance_id": os.environ.get("POLICYGUARD_INSTANCE_ID"), "availability_zone": None,
            "instance_type": None, "region": os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
            "hostname": socket.gethostname(), "on_ec2": False}
    if info["instance_id"]:
        return info
    try:
        token_request = urllib.request.Request(
            f"{IMDS}/api/token", method="PUT", headers={"X-aws-ec2-metadata-token-ttl-seconds": "300"})
        with urllib.request.urlopen(token_request, timeout=1) as response:
            token = response.read().decode()
        info["instance_id"] = _imds("meta-data/instance-id", token)
        info["availability_zone"] = _imds("meta-data/placement/availability-zone", token)
        info["instance_type"] = _imds("meta-data/instance-type", token)
        info["region"] = info["availability_zone"][:-1]
        info["on_ec2"] = True
    except Exception:
        info["instance_id"] = info["instance_id"] or "not-on-ec2"
    return info
