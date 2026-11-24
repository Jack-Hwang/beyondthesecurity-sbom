# src_scan.py
"""
Clean-room implementation of a source scanner for U-Boot device-tree helpers.
Provides conversion utilities and lightweight data structures for drivers,
uclass drivers, structs, and a scanner interface.

This is a minimal, well-documented reimplementation intended to satisfy a
public contract used by other code. It avoids importing terminal/pty
modules so it is safe on all platforms (Windows, POSIX).

Allowed stdlib imports: collections, re, os, sys
"""
from collections import defaultdict
import re
import os
import sys

# Public API names
__all__ = [
    "conv_name_to_c",
    "get_compat_name",
    "Driver",
    "UclassDriver",
    "Struct",
    "Scanner",
]


# Utility: convert device-tree names into valid C identifiers.
# Uses repeated str.replace calls (as required) rather than re.sub.
def conv_name_to_c(name):
    """
    Convert a device-tree name to a C identifier.

    This function performs multiple replace() calls rather than using
    regular expressions. It ensures the returned string is a valid C
    identifier by replacing characters that are not alphanumeric or
    underscore with underscores, collapsing repeated underscores, and
    ensuring it does not start with a digit (prefixing with an underscore
    if necessary).

    Args:
        name (str): Name to convert
    Returns:
        str: String containing the C version of this name
    """
    if name is None:
        return ""
    # Ensure string type
    s = str(name)

    # Common replacements (explicit):
    # replace spaces, slashes, commas, plus, hyphen, colon, period
    # and other punctuation with underscores.
    # We do these with chained replace calls as requested.
    # Start with some obvious ones
    s = s.replace(' ', '_')
    s = s.replace('/', '_')
    s = s.replace(',', '_')
    s = s.replace('+', '_')
    s = s.replace('-', '_')
    s = s.replace(':', '_')
    s = s.replace('.', '_')
    s = s.replace('@', '_')
    s = s.replace('#', '_')
    s = s.replace('%', '_')
    s = s.replace('(', '_')
    s = s.replace(')', '_')
    s = s.replace('[', '_')
    s = s.replace(']', '_')
    s = s.replace('{', '_')
    s = s.replace('}', '_')
    s = s.replace('*', '_')
    s = s.replace('&', '_')
    s = s.replace('=', '_')
    s = s.replace('>', '_')
    s = s.replace('<', '_')
    s = s.replace('?', '_')
    s = s.replace('!', '_')
    s = s.replace('"', '_')
    s = s.replace("'", '_')
    s = s.replace(';', '_')
    s = s.replace('`', '_')
    s = s.replace('~', '_')
    s = s.replace('\n', '_')
    s = s.replace('\t', '_')

    # Collapse runs of non-alphanumeric characters to single underscore.
    # Use a lightweight loop rather than re.sub to follow the spirit of
    # multiple replace calls. However, using a small re here for
    # collapsing underscores is acceptable; but spec requested multiple
    # replace() calls for speed. We'll collapse by manual scan.
    out_chars = []
    prev_underscore = False
    for ch in s:
        # Allow ASCII letters, digits and underscore
        if ('a' <= ch <= 'z') or ('A' <= ch <= 'Z') or ('0' <= ch <= '9') or (ch == '_'):
            if ch == '_':
                if not prev_underscore:
                    out_chars.append(ch)
                prev_underscore = True
            else:
                out_chars.append(ch)
                prev_underscore = False
        else:
            if not prev_underscore:
                out_chars.append('_')
                prev_underscore = True
    result = ''.join(out_chars)

    # Remove leading/trailing underscores
    result = result.strip('_')

    # Ensure it doesn't start with a digit (C identifiers cannot)
    if result and ('0' <= result[0] <= '9'):
        result = '_' + result

    # If empty, return a single underscore
    if not result:
        result = '_'

    return result


def _extract_compatible_list_from_node(node):
    """
    Helper to robustly extract a list of compatible strings from a node.

    This function aims to support several common fdt.Node interfaces seen
    in different python dtb libraries. It will check for attributes in
    the following order and attempt to normalize to a list of strings:
      - node.props (dict-like) with key 'compatible'
      - node.get('compatible') callable
      - node.compatible attribute (list or str)
      - node.props.get('compatible').value (some libraries store a blob)

    If nothing is found, an empty list is returned.
    """
    # Direct attribute 'compatible'
    try:
        comp = getattr(node, 'compatible', None)
        if comp is not None:
            # If it's bytes, decode; if string return single-item list;
            # if iterable, convert elements to str
            if isinstance(comp, (bytes, bytearray)):
                try:
                    return [comp.decode('utf-8')]
                except Exception:
                    return [str(comp)]
            if isinstance(comp, str):
                return [comp]
            try:
                return [str(x) for x in comp]
            except Exception:
                return []
    except Exception:
        pass

    # node.get('compatible') style
    try:
        getmeth = getattr(node, 'get', None)
        if callable(getmeth):
            comp = node.get('compatible')
            if comp is not None:
                if isinstance(comp, (bytes, bytearray)):
                    try:
                        return [comp.decode('utf-8')]
                    except Exception:
                        return [str(comp)]
                if isinstance(comp, str):
                    return [comp]
                try:
                    return [str(x) for x in comp]
                except Exception:
                    return []
    except Exception:
        pass

    # node.props style: dict-like
    try:
        props = getattr(node, 'props', None)
        if props is not None:
            # attempt mapping-like access
            if 'compatible' in props:
                val = props['compatible']
                # Some representations store bytes, or objects with .value
                if isinstance(val, (bytes, bytearray)):
                    try:
                        return [val.decode('utf-8')]
                    except Exception:
                        return [str(val)]
                if hasattr(val, 'value'):
                    v = getattr(val, 'value')
                    if isinstance(v, (bytes, bytearray)):
                        try:
                            return [v.decode('utf-8')]
                        except Exception:
                            return [str(v)]
                    if isinstance(v, str):
                        return [v]
                    try:
                        return [str(x) for x in v]
                    except Exception:
                        return []
                if isinstance(val, str):
                    return [val]
                try:
                    return [str(x) for x in val]
                except Exception:
                    return []
    except Exception:
        pass

    # Fallback: nothing found
    return []


def get_compat_name(node):
    """
    Get the node's list of compatible strings as C identifiers.

    Args:
        node (fdt.Node): Node object to check
    Returns:
        list of str: List of C identifiers for all the compatible strings
    """
    compat_list = _extract_compatible_list_from_node(node)
    result = []
    for c in compat_list:
        if not isinstance(c, str):
            try:
                c = c.decode('utf-8')
            except Exception:
                c = str(c)
        # Convert each compatible string to a C identifier
        result.append(conv_name_to_c(c))
    return result


# Data classes for Driver, UclassDriver, Struct
class Driver(object):
    """
    Information about a driver in U-Boot.

    Attributes are public and may be set by scanner code.
    """

    def __init__(self, name):
        self.name = name  # e.g. 'x' for U_BOOT_DRIVER(x)
        self.fname = None
        self.uclass_id = None
        # compat: mapping from compatible string to driver data or None
        self.compat = dict()
        self.priv = None
        self.plat = None
        self.child_priv = None
        self.child_plat = None
        self.used = False
        self.phase = None

    def __repr__(self):
        return "<Driver name={!r} fname={!r}>".format(self.name, self.fname)


class UclassDriver(object):
    """
    Holds information about a uclass driver.
    """

    def __init__(self, name):
        self.name = name  # e.g. 'i2c' for UCLASS_I2C
        self.uclass_id = None
        self.priv = None
        self.per_dev_priv = None
        self.per_dev_plat = None
        self.per_child_priv = None
        self.per_child_plat = None
        # alias mappings
        self.alias_num_to_node = dict()
        self.alias_path_to_num = dict()

    def __repr__(self):
        return "<UclassDriver name={!r}>".format(self.name)


class Struct(object):
    """
    Holds information about a struct definition.
    """

    def __init__(self, name):
        self.name = name
        self.fname = None  # filename as C include path

    def __repr__(self):
        return "<Struct name={!r} fname={!r}>".format(self.name, self.fname)


class Scanner(object):
    """
    Scanner for U-Boot source tree. This is a lightweight, minimal
    implementation that provides the methods and properties expected by
    callers. It does not perform a full parse of C source; rather, it
    offers an interface for callers to populate and query driver information.
    """

    def __init__(self, basedir=None):
        # Default base directory: two levels up from this file
        if basedir is None:
            this_dir = os.path.dirname(os.path.abspath(__file__))
            basedir = os.path.normpath(os.path.join(this_dir, '..', '..'))
        self._basedir = basedir

        # Dicts for drivers and aliases
        self._drivers = dict()  # name -> Driver
        self._driver_aliases = dict()  # alias -> real driver name
        self._drivers_additional = []
        # Warnings keyed by driver name -> set of strings
        self._warnings = defaultdict(set)
        # of_match: name -> dict of compatible info
        self._of_match = dict()
        # uclass drivers
        self._uclasses = dict()  # name -> UclassDriver
        # structs
        self._structs = dict()

    # Simple utility methods
    def get_driver(self, name):
        """Return Driver object for name, creating one if necessary."""
        if name in self._driver_aliases:
            name = self._driver_aliases[name]
        d = self._drivers.get(name)
        if d is None:
            d = Driver(name)
            self._drivers[name] = d
        return d

    def get_normalized_compat_name(self, compat):
        """Return normalized compat (C identifier) for a given string."""
        return conv_name_to_c(compat)

    def show_warnings(self):
        """Return a copy of warnings collected by the scanner."""
        return {k: set(v) for k, v in self._warnings.items()}

    def scan_driver(self, fname):
        """Stub: scan a driver file and return a Driver instance.

        This does not perform real parsing: it creates a Driver whose
        fname is set and whose name is derived from the filename base.
        Callers may override or extend this behavior.
        """
        base = os.path.basename(fname)
        name, _ = os.path.splitext(base)
        d = self.get_driver(name)
        d.fname = fname
        return d

    def scan_header(self, fname):
        """Stub: scan a header file for structs. Returns list of Struct."""
        # Use file basename (without extension) as a struct name candidate
        base = os.path.basename(fname)
        name, _ = os.path.splitext(base)
        s = Struct(name)
        s.fname = fname
        self._structs[name] = s
        return [s]

    def scan_drivers(self, drivers_dir=None):
        """Scan a directory for driver files.

        This is a lightweight directory walk implementation that will
        consider any file under drivers_dir as a driver source and will
        create Driver objects for them. Returns list of Driver objects.
        """
        if drivers_dir is None:
            drivers_dir = os.path.join(self._basedir, 'drivers')
        found = []
        if not os.path.isdir(drivers_dir):
            return found
        for root, dirs, files in os.walk(drivers_dir):
            for fn in files:
                if fn.endswith(('.c', '.h', '.S')):
                    fpath = os.path.join(root, fn)
                    d = self.scan_driver(fpath)
                    found.append(d)
        return found

    def mark_used(self, driver_name):
        """Mark a driver as used by name.

        If the driver does not exist yet, it will be created.
        """
        d = self.get_driver(driver_name)
        d.used = True

    def add_uclass_alias(self, uclass_name, alias_num, node_path):
        """Add an alias mapping for a uclass.

        alias_num: integer sequence number
        node_path: string path to node
        """
        uc = self._uclasses.get(uclass_name)
        if uc is None:
            uc = UclassDriver(uclass_name)
            self._uclasses[uclass_name] = uc
        uc.alias_num_to_node[alias_num] = node_path
        uc.alias_path_to_num[node_path] = alias_num

    def assign_seq(self, uclass_name, node_path):
        """Assign and return a sequence number for node_path in uclass.

        If the node_path already has a sequence number, return it. Otherwise
        allocate the next available integer (starting at 0) and return it.
        """
        uc = self._uclasses.get(uclass_name)
        if uc is None:
            uc = UclassDriver(uclass_name)
            self._uclasses[uclass_name] = uc
        if node_path in uc.alias_path_to_num:
            return uc.alias_path_to_num[node_path]
        # find next free integer
        i = 0
        while i in uc.alias_num_to_node:
            i += 1
        uc.alias_num_to_node[i] = node_path
        uc.alias_path_to_num[node_path] = i
        return i

    # Additional small helpers
    @property
    def basedir(self):
        return self._basedir

    @property
    def drivers(self):
        return dict(self._drivers)

    @property
    def uclasses(self):
        return dict(self._uclasses)

    @property
    def structs(self):
        return dict(self._structs)


# Module quick test when run directly (very lightweight)
if __name__ == '__main__':
    s = Scanner()
    print('basedir:', s.basedir)
    d = s.scan_driver('drivers/example_driver.c')
    print('scanned driver:', d)
    print('conv:', conv_name_to_c('rockchip,rk3288-grf'))
