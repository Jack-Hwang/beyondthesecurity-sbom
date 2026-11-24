# Clean-room spec: src_scan

Why reimplementation: clean-room reimplementation of the u-boot dtoc source scanner (GPL-2.0 isolation scenario, 16384-token generation retry)

## Requirements

- reimplement the public surface below as a NEW module named `src_scan.py`
- same public names and signatures; behaviour follows each contract
- no third-party dependencies beyond: collections, re, os, sys

## Function contracts
- `conv_name_to_c(name)`:
  Convert a device-tree name to a C identifier
  
  This uses multiple replace() calls instead of re.sub() since it is faster
  (400ms for 1m calls versus 1000ms for the 're' version).
  
  Args:
  name (str): Name to convert
  Return:
  str: String containing the C version of this name
- `get_compat_name(node)`:
  Get the node's list of compatible string as a C identifiers
  
  Args:
  node (fdt.Node): Node object to check
  Return:
  list of str: List of C identifiers for all the compatible strings

## Class contracts
- `Driver` methods (none): Information about a driver in U-Boot

Attributes:
    name: Name of driver. For U_BOOT_DRIVER(x) this is 'x'
    fname: Filename where the driver was found
    uclass_id: Name of uclass, e.g. 'UCLASS_I2C'
    compat: Driver data for each compatible string:
        key: Compatible string, e.g. 'rockchip,rk3288-grf'
        value: Driver data, e,g, 'ROCKCHIP_SYSCON_GRF', or None
    fname: Filename where the driver was found
    priv (str): struct name of the priv_auto member, e.g. 'serial_priv'
    plat (str): struct name of the plat_auto member, e.g. 'serial_plat'
    child_priv (str): struct name of the per_child_auto member,
        e.g. 'pci_child_priv'
    child_plat (str): struct name of the per_child_plat_auto member,
        e.g. 'pci_child_plat'
    used (bool): True if the driver is used by the structs being output
    phase (str): Which phase of U-Boot to use this driver
    he
- `UclassDriver` methods (none): Holds information about a uclass driver

Attributes:
    name: Uclass name, e.g. 'i2c' if the driver is for UCLASS_I2C
    uclass_id: Uclass ID, e.g. 'UCLASS_I2C'
    priv: struct name of the private data, e.g. 'i2c_priv'
    per_dev_priv (str): struct name of the priv_auto member, e.g. 'spi_info'
    per_dev_plat (str): struct name of the plat_auto member, e.g. 'i2c_chip'
    per_child_priv (str): struct name of the per_child_auto member,
        e.g. 'pci_child_priv'
    per_child_plat (str): struct name of the per_child_plat_auto member,
        e.g. 'pci_child_plat'
    alias_num_to_node (dict): Aliases for this uclasses (for sequence
            numbers)
        key (int): Alias number, e.g. 2 for "pci2"
        value (str): Node the alias points to
    alias_path_to_num (dict): Convert a path to an alias number
        key (str): Full path to node (e.g. '/soc/pci')
        seq (int
- `Struct` methods (none): Holds information about a struct definition

Attributes:
    name: Struct name, e.g. 'fred' if the struct is 'struct fred'
    fname: Filename containing the struct, in a format that C files can
        include, e.g. 'asm/clk.h'
- `Scanner` methods get_driver, get_normalized_compat_name, show_warnings, scan_driver, scan_header, scan_drivers, mark_used, add_uclass_alias, assign_seq: Scanning of the U-Boot source tree

Properties:
    _basedir (str): Base directory of U-Boot source code. Defaults to the
        grandparent of this file's directory
    _drivers: Dict of valid driver names found in drivers/
        key: Driver name
        value: Driver for that driver
    _driver_aliases: Dict that holds aliases for driver names
        key: Driver alias declared with
            DM_DRIVER_ALIAS(driver_alias, driver_name)
        value: Driver name declared with U_BOOT_DRIVER(driver_name)
    _drivers_additional (list or str): List of additional drivers to use
        during scanning
    _warnings: Dict of warnings found:
        key: Driver name
        value: Set of warnings
    _of_match: Dict holding information about compatible strings
        key: Name of struct udevice_id variable
        value: Dict of compatible info in that variable:
           key: Compatib

## Clean-room rule

Write original code. Do not reproduce any existing implementation text.
