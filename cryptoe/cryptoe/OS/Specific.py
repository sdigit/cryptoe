from os import uname

_FUNCTIONS = {
    'Linux': {
        'uptime': 'linux_proc_uptime',
    }
}


def linux_proc_uptime():
    if uname()[0] != 'Linux':
        raise OSError('this function is not for this OS')
    ut_str = open('/proc/uptime').read().rstrip()
    uv = ut_str.split()
    bsec = uv[0].split('.')
    isec = uv[1].split('.')
    ret = [
        [4, int(bsec[0])],
        [1, int(bsec[1])],
        [4, int(isec[0])],
        [1, int(isec[1])],
    ]
    return ret


def netbsd_boottime():
    if uname()[0] != 'NetBSD':
        raise OSError('this function is not for this OS')
