"""
The MD5 skapi-js uses to name accounts ("<service>-<md5(e-mail or username)>"), ported literally.

It works on UTF-16 code units, not UTF-8 bytes: for ASCII it equals hashlib.md5, for U+0080..U+00FF
it equals MD5 of the latin-1 bytes, and above U+00FF it gives digests no standard MD5 produces. A
username must hash exactly as skapi-js hashes it, or that account cannot sign in from Python.
"""

from __future__ import annotations

M = 0xFFFFFFFF


def _ad(x: int, y: int) -> int:
    return (x + y) & M


def _rl(n: int, c: int) -> int:
    return ((n << c) | (n >> (32 - c))) & M


def _cm(q, a, b, x, s, t):
    return _ad(_rl(_ad(_ad(a, q), _ad(x, t)), s), b)


def _ff(a, b, c, d, x, s, t):
    return _cm((b & c) | (~b & M & d), a, b, x, s, t)


def _gg(a, b, c, d, x, s, t):
    return _cm((b & d) | (c & ~d & M), a, b, x, s, t)


def _hh(a, b, c, d, x, s, t):
    return _cm(b ^ c ^ d, a, b, x, s, t)


def _ii(a, b, c, d, x, s, t):
    return _cm(c ^ (b | (~d & M)), a, b, x, s, t)


def _u(n: int) -> int:
    return n & M


_ROUNDS = [
    (_ff, [(0, 7, -680876936), (1, 12, -389564586), (2, 17, 606105819), (3, 22, -1044525330), (4, 7, -176418897), (5, 12, 1200080426),
           (6, 17, -1473231341), (7, 22, -45705983), (8, 7, 1770035416), (9, 12, -1958414417), (10, 17, -42063), (11, 22, -1990404162),
           (12, 7, 1804603682), (13, 12, -40341101), (14, 17, -1502002290), (15, 22, 1236535329)]),
    (_gg, [(1, 5, -165796510), (6, 9, -1069501632), (11, 14, 643717713), (0, 20, -373897302), (5, 5, -701558691), (10, 9, 38016083),
           (15, 14, -660478335), (4, 20, -405537848), (9, 5, 568446438), (14, 9, -1019803690), (3, 14, -187363961), (8, 20, 1163531501),
           (13, 5, -1444681467), (2, 9, -51403784), (7, 14, 1735328473), (12, 20, -1926607734)]),
    (_hh, [(5, 4, -378558), (8, 11, -2022574463), (11, 16, 1839030562), (14, 23, -35309556), (1, 4, -1530992060), (4, 11, 1272893353),
           (7, 16, -155497632), (10, 23, -1094730640), (13, 4, 681279174), (0, 11, -358537222), (3, 16, -722521979), (6, 23, 76029189),
           (9, 4, -640364487), (12, 11, -421815835), (15, 16, 530742520), (2, 23, -995338651)]),
    (_ii, [(0, 6, -198630844), (7, 10, 1126891415), (14, 15, -1416354905), (5, 21, -57434055), (12, 6, 1700485571), (3, 10, -1894986606),
           (10, 15, -1051523), (1, 21, -2054922799), (8, 6, 1873313359), (15, 10, -30611744), (6, 15, -1560198380), (13, 21, 1309151649),
           (4, 6, -145523070), (11, 10, -1120210379), (2, 15, 718787259), (9, 21, -343485551)]),
]


def md5_js(text: str) -> str:
    units = list(text.encode("utf-16-le"))
    codes = [units[i] | (units[i + 1] << 8) for i in range(0, len(units), 2)]
    length = len(codes)
    num_blocks = ((length + 8) >> 6) + 1
    x = [0] * (num_blocks * 16)
    for i, cu in enumerate(codes):
        x[i >> 2] |= (cu << ((i % 4) * 8)) & M
    x[length >> 2] |= (0x80 << ((length % 4) * 8)) & M
    x[num_blocks * 16 - 2] = (length * 8) & M

    a, b, c, d = _u(1732584193), _u(-271733879), _u(-1732584194), _u(271733878)
    for i in range(0, len(x), 16):
        la, lb, lc, ld = a, b, c, d
        for fn, steps in _ROUNDS:
            for n, (k, s, t) in enumerate(steps):
                t = _u(t)
                if n % 4 == 0:
                    a = fn(a, b, c, d, x[i + k], s, t)
                elif n % 4 == 1:
                    d = fn(d, a, b, c, x[i + k], s, t)
                elif n % 4 == 2:
                    c = fn(c, d, a, b, x[i + k], s, t)
                else:
                    b = fn(b, c, d, a, x[i + k], s, t)
        a, b, c, d = _ad(a, la), _ad(b, lb), _ad(c, lc), _ad(d, ld)

    alphabet = "0123456789abcdef"

    def rh(n):
        return "".join(alphabet[(n >> (j * 8 + 4)) & 0x0F] + alphabet[(n >> (j * 8)) & 0x0F] for j in range(4))

    return rh(a) + rh(b) + rh(c) + rh(d)
