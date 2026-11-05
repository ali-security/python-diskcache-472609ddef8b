"""Test diskcache safe unpickling of keys and values (CVE-2025-69872)."""

import collections as co
import datetime
import decimal
import fractions
import io
import os
import os.path as op
import pickle
import shutil
import sqlite3
import subprocess
import sys
import tempfile

import pytest

import diskcache as dc
from diskcache.core import DBNAME, MODE_PICKLE, Constant


class Exploit:
    """Malicious object: unpickling it calls `func` with `args`."""

    def __init__(self, func, *args):
        self.func = func
        self.args = args

    def __reduce__(self):
        return self.func, self.args


class SafeCustomClass:
    """Class that an application may intentionally store in the cache."""

    def __init__(self, value=42):
        self.value = value

    def __eq__(self, other):
        return isinstance(other, SafeCustomClass) and self.value == other.value


class FixedSignatureDisk(dc.Disk):
    """Disk subclass without `allowed_classes` that skips Disk.__init__."""

    def __init__(self, directory, min_file_size=0, pickle_protocol=0):
        # pylint: disable=super-init-not-called
        self._directory = directory
        self.min_file_size = min_file_size
        self.pickle_protocol = pickle_protocol


class LenientDisk(dc.Disk):
    """Disk subclass that ignores unknown keyword arguments."""

    def __init__(self, directory, min_file_size=0, pickle_protocol=0, **_):
        super().__init__(directory, min_file_size, pickle_protocol)


ALLOWED = {(SafeCustomClass.__module__, SafeCustomClass.__qualname__)}
UNSAFE = dc.UNSAFE_PICKLE_ALLOW_ALL

# Protocol 4 pickle of the global "builtins.object.__subclasses__". The
# dotted name walks attributes of the allowed `object` class.
DOTTED_NAME = (
    b'\x80\x04'  # PROTO 4
    b'\x8c\x08builtins'  # SHORT_BINUNICODE
    b'\x8c\x15object.__subclasses__'  # SHORT_BINUNICODE
    b'\x93'  # STACK_GLOBAL
    b'.'  # STOP
)

SAFE_TYPES = (
    bool,
    bytearray,
    bytes,
    complex,
    dict,
    float,
    frozenset,
    int,
    list,
    object,
    range,
    set,
    slice,
    str,
    tuple,
)

SAFE_VALUES = [
    None,
    True,
    2**100,
    1 + 2j,
    ('text', b'bytes', bytearray(b'bytearray')),
    [1, 'two', 3.0],
    {'a': [1, 2]},
    {1, 2, 3},
    frozenset([1, 2, 3]),
    range(1, 10, 2),
    slice(1, 10, 2),
    co.OrderedDict([('a', 1), ('b', 2)]),
    co.defaultdict(list, a=[1]),
    co.deque([1, 2], maxlen=5),
    datetime.date(2023, 1, 15),
    datetime.datetime(2023, 1, 15, 10, 30, tzinfo=datetime.timezone.utc),
    datetime.time(10, 30),
    datetime.timedelta(days=1, seconds=2),
    datetime.timezone(datetime.timedelta(hours=2), 'UTC+2'),
    decimal.Decimal('3.14159'),
    fractions.Fraction(1, 3),
    SAFE_TYPES,
]

PROTOCOLS = list(range(pickle.HIGHEST_PROTOCOL + 1))


@pytest.fixture
def directory():
    path = tempfile.mkdtemp(prefix='diskcache-')
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def marker():
    """Path that the exploit payload creates when it is executed."""
    parent = tempfile.mkdtemp(prefix='diskcache-marker-')
    yield op.join(parent, 'pwned')
    shutil.rmtree(parent, ignore_errors=True)


def payload(marker):
    """Return pickle that creates the `marker` directory when loaded."""
    return pickle.dumps(Exploit(os.makedirs, marker))


def sql(directory, statement, params=()):
    """Run `statement` on the cache database directly, like an attacker."""
    con = sqlite3.connect(op.join(directory, DBNAME))
    try:
        with con:
            return con.execute(statement, params).fetchall()
    finally:
        con.close()


def blocked():
    return pytest.raises(pickle.UnpicklingError, match='Disallowed class')


def test_payload_runs_when_unrestricted(directory, marker):
    # Control: unrestricted (legacy) unpickling runs the payload, so the
    # tests below exercise a real code execution vector.
    with dc.Cache(directory) as cache:
        cache['key'] = ('value',)

    sql(directory, 'UPDATE Cache SET value = ?', (payload(marker),))

    with dc.Cache(directory, allowed_classes=UNSAFE) as cache:
        assert cache['key'] is None

    assert op.isdir(marker)
    assert pickle.loads(DOTTED_NAME) == object.__subclasses__


@pytest.mark.parametrize(
    'read',
    [
        lambda cache: cache['key'],
        lambda cache: cache.get('key'),
        lambda cache: cache.pop('key'),
        lambda cache: cache.peekitem(),
    ],
    ids=['getitem', 'get', 'pop', 'peekitem'],
)
def test_value_in_database(directory, marker, read):
    with dc.Cache(directory) as cache:
        cache['key'] = ('value',)

    sql(directory, 'UPDATE Cache SET value = ?', (payload(marker),))

    with dc.Cache(directory) as cache:
        with blocked():
            read(cache)

    assert not op.exists(marker)


def test_value_in_file(directory, marker):
    with dc.Cache(directory) as cache:
        cache['key'] = ['x' * 2**16]

    ((mode, filename),) = sql(directory, 'SELECT mode, filename FROM Cache')
    assert mode == MODE_PICKLE
    assert filename is not None

    with open(op.join(directory, filename), 'wb') as writer:
        writer.write(payload(marker))

    with dc.Cache(directory) as cache:
        with blocked():
            cache['key']

    assert not op.exists(marker)


def test_key_in_database(directory, marker):
    with dc.Cache(directory) as cache:
        cache[('key',)] = 'value'

    sql(directory, 'UPDATE Cache SET key = ?', (payload(marker),))

    with dc.Cache(directory) as cache:
        with blocked():
            list(cache)
        with blocked():
            cache.peekitem()

    assert not op.exists(marker)


@pytest.mark.parametrize('disk', [dc.Disk, LenientDisk])
def test_settings_table_cannot_allow_all(directory, marker, disk):
    with dc.Cache(directory, disk=disk) as cache:
        cache['key'] = ('value',)

    sql(directory, 'UPDATE Cache SET value = ?', (payload(marker),))
    # Settings with the "disk_" prefix are set as Disk attributes.
    for key, value in [
        ('disk_allowed_classes', UNSAFE),
        ('disk__allowed_classes', None),
        ('_allowed_classes', UNSAFE),
    ]:
        sql(directory, 'INSERT INTO Settings VALUES (?, ?)', (key, value))

    with dc.Cache(directory, disk=disk) as cache:
        with blocked():
            cache['key']

        clone = pickle.loads(pickle.dumps(cache))
        try:
            with blocked():
                clone['key']
        finally:
            clone.close()

    assert not op.exists(marker)


@pytest.mark.parametrize(
    'func, args',
    [
        (os.system, ('echo pwned',)),
        (subprocess.call, ([sys.executable, '-c', 'pass'],)),
        (eval, ('1 + 1',)),
        (exec, ('pass',)),
        (getattr, ('', 'join')),
        (__import__, ('os',)),
        (type, ('Pwned', (), {})),
        (pickle.loads, (pickle.dumps(None),)),
    ],
    ids=[
        'os.system',
        'subprocess.call',
        'eval',
        'exec',
        'getattr',
        '__import__',
        'type',
        'pickle.loads',
    ],
)
def test_payloads_blocked(directory, func, args):
    data = sqlite3.Binary(pickle.dumps(Exploit(func, *args)))
    disk = dc.Disk(directory)

    with blocked():
        disk.get(data, False)

    with blocked():
        disk.fetch(MODE_PICKLE, None, data, False)


def test_dotted_name_blocked(directory):
    disk = dc.Disk(directory)

    with blocked():
        disk.fetch(MODE_PICKLE, None, DOTTED_NAME, False)


def test_deque_value_in_database(directory, marker):
    deque = dc.Deque([('value',)], directory)
    deque.cache.close()

    sql(directory, 'UPDATE Cache SET value = ?', (payload(marker),))

    deque = dc.Deque(directory=directory)
    try:
        with blocked():
            deque.popleft()
    finally:
        deque.cache.close()

    assert not op.exists(marker)


def test_index_value_in_database(directory, marker):
    index = dc.Index(directory, {'key': ('value',)})
    index.cache.close()

    sql(directory, 'UPDATE Cache SET value = ?', (payload(marker),))

    index = dc.Index(directory)
    try:
        with blocked():
            index['key']
    finally:
        index.cache.close()

    assert not op.exists(marker)


def test_fanout_value_in_database(directory, marker):
    with dc.FanoutCache(directory, shards=1) as cache:
        cache['key'] = ('value',)

    shard = op.join(directory, '000')
    sql(shard, 'UPDATE Cache SET value = ?', (payload(marker),))

    with dc.FanoutCache(directory, shards=1) as cache:
        with blocked():
            cache['key']

    assert not op.exists(marker)


def test_custom_class_blocked_by_default(directory):
    with dc.Cache(directory, allowed_classes=UNSAFE) as cache:
        cache['key'] = SafeCustomClass()

    with dc.Cache(directory) as cache:
        with pytest.raises(pickle.UnpicklingError) as excinfo:
            cache['key']

    message = str(excinfo.value)
    assert 'Disallowed class' in message
    assert 'SafeCustomClass' in message
    assert 'allowed_classes' in message


@pytest.mark.parametrize('protocol', PROTOCOLS)
def test_safe_values(directory, protocol):
    with dc.Cache(directory, disk_pickle_protocol=protocol) as cache:
        for num, value in enumerate(SAFE_VALUES):
            cache[num] = value
            cache[value] = num

        for num, value in enumerate(SAFE_VALUES):
            result = cache[num]
            assert result == value
            assert type(result) is type(value)

        assert list(cache) == [
            item for pair in enumerate(SAFE_VALUES) for item in pair
        ]


def test_constant_in_key(directory):
    # memoize_stampede stores keys that end with ENOVAL.
    with dc.Cache(directory) as cache:
        assert cache.add(('func', 1, None, dc.ENOVAL), None)
        ((name, num, none, constant),) = list(cache)

    assert (name, num, none) == ('func', 1, None)
    assert isinstance(constant, Constant)


@pytest.mark.parametrize('protocol', PROTOCOLS)
def test_allowed_classes(directory, protocol):
    value = SafeCustomClass(99)

    with dc.Cache(
        directory,
        allowed_classes=ALLOWED,
        disk_pickle_protocol=protocol,
    ) as cache:
        cache['key'] = value
        cache[('key', value)] = 'value'

        assert cache['key'] == value
        assert list(cache) == ['key', ('key', value)]


def test_allowed_classes_pairs(directory):
    allowed = [list(pair) for pair in ALLOWED]

    with dc.Cache(directory, allowed_classes=allowed) as cache:
        cache['key'] = SafeCustomClass(7)
        assert cache['key'] == SafeCustomClass(7)


def test_unsafe_allows_all(directory):
    with dc.Cache(directory, allowed_classes=UNSAFE) as cache:
        cache['key'] = SafeCustomClass(5)
        assert cache['key'] == SafeCustomClass(5)


def test_allowed_classes_not_in_settings(directory):
    with dc.Cache(directory, allowed_classes=UNSAFE):
        pass

    keys = [key for (key,) in sql(directory, 'SELECT key FROM Settings')]
    assert not any('allowed_classes' in key for key in keys)


def test_pickle_cache(directory):
    with dc.Cache(directory, allowed_classes=ALLOWED) as cache:
        cache['key'] = SafeCustomClass(1)

        clone = pickle.loads(pickle.dumps(cache))
        try:
            assert clone['key'] == SafeCustomClass(1)
        finally:
            clone.close()

        # State pickled before allowed_classes existed uses the defaults.
        clone = dc.Cache.__new__(dc.Cache)
        clone.__setstate__((cache.directory, cache.timeout, dc.Disk))
        try:
            with blocked():
                clone['key']
        finally:
            clone.close()


def test_custom_disk(directory, marker):
    with dc.Cache(directory, disk=FixedSignatureDisk) as cache:
        cache['key'] = ('value',)
        assert cache['key'] == ('value',)

    sql(directory, 'UPDATE Cache SET value = ?', (payload(marker),))

    with dc.Cache(directory, disk=FixedSignatureDisk) as cache:
        with blocked():
            cache['key']

    assert not op.exists(marker)


@pytest.mark.parametrize(
    'allowed', [ALLOWED, UNSAFE], ids=['allowed', 'unsafe']
)
def test_custom_disk_allowed_classes(directory, allowed):
    disk = FixedSignatureDisk

    with dc.Cache(directory, disk=disk, allowed_classes=allowed) as cache:
        cache['key'] = SafeCustomClass(8)
        assert cache['key'] == SafeCustomClass(8)

    with dc.Cache(directory, disk=disk) as cache:
        with blocked():
            cache['key']


def test_allowed_classes_invalid_string(directory):
    with pytest.raises(ValueError, match='allowed_classes'):
        dc.Disk(directory, allowed_classes='builtins.eval')


def test_json_disk(directory):
    with dc.Cache(directory, disk=dc.JSONDisk, allowed_classes=ALLOWED) as c:
        c['key'] = {'value': [1, 2, 3]}
        assert c['key'] == {'value': [1, 2, 3]}


def test_fanout_allowed_classes(directory):
    value = SafeCustomClass(3)

    with dc.FanoutCache(directory, allowed_classes=ALLOWED) as cache:
        cache['key'] = value
        sub_cache = cache.cache('sub')
        sub_cache['key'] = value
        other_cache = cache.cache('other')
        other_cache['key'] = value
        deque = cache.deque('deque')
        deque.append(value)
        index = cache.index('index')
        index['key'] = value

        assert cache['key'] == value
        assert sub_cache['key'] == value
        assert deque[0] == value
        assert index['key'] == value

        clone = pickle.loads(pickle.dumps(cache))
        try:
            assert clone['key'] == value
        finally:
            clone.close()

        for item in (sub_cache, other_cache, deque.cache, index.cache):
            item.close()

    with dc.FanoutCache(directory) as cache:
        with blocked():
            cache['key']
        with blocked():
            cache.cache('sub')['key']
        with blocked():
            cache.deque('deque')[0]
        with blocked():
            cache.index('index')['key']

        other_cache = cache.cache('other', allowed_classes=UNSAFE)
        assert other_cache['key'] == value

        for item in (
            cache.cache('sub'),
            other_cache,
            cache.deque('deque').cache,
            cache.index('index').cache,
        ):
            item.close()


def test_djangocache_default_allows_all(directory):
    from diskcache.djangocache import DjangoCache

    params = {'SHARDS': 1, 'OPTIONS': {}}
    cache = DjangoCache(directory, params)
    try:
        assert cache.set('key', SafeCustomClass(4))
        assert cache.get('key') == SafeCustomClass(4)
    finally:
        cache.close()

    assert params == {'SHARDS': 1, 'OPTIONS': {}}


def test_djangocache_custom_disk(directory):
    from diskcache.djangocache import DjangoCache

    params = {'SHARDS': 1, 'OPTIONS': {'disk': FixedSignatureDisk}}
    cache = DjangoCache(directory, params)
    try:
        assert cache.set('key', SafeCustomClass(6))
        assert cache.get('key') == SafeCustomClass(6)
    finally:
        cache.close()


def test_djangocache_allowed_classes_option(directory, marker):
    from diskcache.djangocache import DjangoCache

    params = {'SHARDS': 1, 'OPTIONS': {'allowed_classes': None}}
    cache = DjangoCache(directory, params)
    try:
        assert cache.set('key', ('value',))
        shard = op.join(directory, '000')
        sql(shard, 'UPDATE Cache SET value = ?', (payload(marker),))
        with blocked():
            cache.get('key')
    finally:
        cache.close()

    assert not op.exists(marker)


def test_safe_unpickler():
    assert 'SafeUnpickler' in dc.__all__
    assert 'UNSAFE_PICKLE_ALLOW_ALL' in dc.__all__

    data = pickle.dumps(SafeCustomClass(1))

    with pytest.raises(pickle.UnpicklingError, match='SafeCustomClass'):
        dc.SafeUnpickler(io.BytesIO(data), set()).load()

    unpickler = dc.SafeUnpickler(io.BytesIO(data), ALLOWED)
    assert unpickler.load() == SafeCustomClass(1)
