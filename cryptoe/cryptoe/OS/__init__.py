from os import uname

__author__ = 'Sean Davis <dive@endersgame.net>'
__all__ = ['LNXKeyring', 'Specific']
from cryptoe.OS import LNXKeyring
from cryptoe.OS import Specific

_os_name = uname()[0]

function_map = getattr(Specific, '_FUNCTIONS')[_os_name]
get_sys_uptime = getattr(Specific, function_map['uptime'])
