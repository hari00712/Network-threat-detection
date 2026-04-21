import os
from logger import write_log

blocked_ips = set()


def block_ip(ip):
    try:
        write_log(f"BLOCK REQUEST: {ip}")

        os.system(
            f'netsh advfirewall firewall add rule '
            f'name="Block_{ip}" dir=in action=block remoteip={ip} profile=any'
        )

        blocked_ips.add(ip)
        write_log(f"BLOCK SUCCESS: {ip}")

        return True

    except Exception as e:
        write_log(f"BLOCK ERROR: {ip} | {e}")
        return False


def unblock_ip(ip):
    try:
        write_log(f"UNBLOCK REQUEST: {ip}")

        os.system(
            f'netsh advfirewall firewall delete rule name="Block_{ip}"'
        )

        blocked_ips.discard(ip)
        write_log(f"UNBLOCK SUCCESS: {ip}")

        return True

    except Exception as e:
        write_log(f"UNBLOCK ERROR: {ip} | {e}")
        return False


def is_blocked(ip):
    return ip in blocked_ips