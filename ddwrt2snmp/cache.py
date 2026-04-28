"""Thread-safe OID -> SNMPValue store with lexicographic GetNext."""

import threading
from bisect import bisect_right


class OIDCache:
    def __init__(self):
        self._lock = threading.Lock()
        self._data = {}            # oid_tuple -> SNMPValue
        self._sorted = []          # cached sorted list of OID tuples
        self._dirty = True         # True when sorted list needs rebuild

    def set(self, oid, value):
        with self._lock:
            if oid not in self._data:
                self._dirty = True
            self._data[oid] = value

    def delete(self, oid):
        with self._lock:
            if self._data.pop(oid, None) is not None:
                self._dirty = True

    def bulk_replace(self, mapping):
        """Replace the entire cache atomically."""
        with self._lock:
            self._data = dict(mapping)
            self._dirty = True

    def bulk_update(self, mapping):
        with self._lock:
            for oid, value in mapping.items():
                if oid not in self._data:
                    self._dirty = True
                self._data[oid] = value

    def get(self, oid):
        with self._lock:
            return self._data.get(oid)

    def get_next(self, oid):
        """Smallest OID strictly greater than `oid`. Returns (oid, value) or None."""
        with self._lock:
            self._refresh_sorted()
            i = bisect_right(self._sorted, oid)
            if i >= len(self._sorted):
                return None
            next_oid = self._sorted[i]
            return next_oid, self._data[next_oid]

    def snapshot(self):
        with self._lock:
            return dict(self._data)

    def _refresh_sorted(self):
        if self._dirty:
            self._sorted = sorted(self._data.keys())
            self._dirty = False
