
# this was written as a project for a university class, and is a little rough around the edges. if you're looking for a library that does something similar, check out python's built in [ipaddress](https://docs.python.org/3/library/ipaddress.html) module instead

# setup
requires python >= 3.11. install via:
```
pip install git+https://github.com/adrianmgg/ipv6thing.git
```

# testing
to run unit tests:
```
python -m unittest discover -s tests
```

to run type checking (requires mypy, `python -m pip install mypy`):
```
python -m mypy -p ipv6thing
```

to check stub files against runtime types (requires mypy, `python -m pip install mypy`):
```
python -m mypy.stubtest ipv6thing
```

# usage

```pycon
>>> from ipv6thing import Address, Network
>>> # you can create addresses from either integers or strings
>>> Address('2001:db8::')
Address(2001:db8::)
>>> Address(0x2001_0db8_0000_0000_0000_0000_0000_0000)
Address(2001:db8::)
>>> # and create networks from a single string, or from an address (or anything that can be turned into one) and a port
>>> Network('2001:db8::/32')
Network(2001:db8::/32)
>>> Network(Address('2001:db8::'), 32)
Network(2001:db8::/32)
>>> Network('2001:db8::', 32)
Network(2001:db8::/32)
>>> Network(0x2001_0db8_0000_0000_0000_0000_0000_0000, 32) 
Network(2001:db8::/32)

>>> # you can test if a given address is in a network
>>> Address('2001:db8::1234') in Network('2001:db8::/32')
True
>>> Address('2001:db9::') in Network('2001:db8::/32')
False

>>> Network('2001:db8::/32').prefix_len
32
>>> hex(Network('2001:db8::/32').prefix_mask)
'0xffffffffffffffffffffffff00000000'

>>> # you can iterate over a network to get the addresses inside it
>>> for addr in Network('2001:db8::/126'):
...     print(addr)
2001:db8::
2001:db8::1
2001:db8::2
2001:db8::3
>>> list(Network('2001:db8::/124')) 
[Address(2001:db8::), Address(2001:db8::1), Address(2001:db8::2), Address(2001:db8::3), Address(2001:db8::4), Address(2001:db8::5), Address(2001:db8::6), Address(2001:db8::7), Address(2001:db8::8), Address(2001:db8::9), Address(2001:db8::a), Address(2001:db8::b), Address(2001:db8::c), Address(2001:db8::d), Address(2001:db8::e), Address(2001:db8::f)]
>>> # as well as index into them arbitrarily
>>> Network('2001:db8::/32')[0]
Address(2001:db8::)
>>> Network('2001:db8::/32')[123456789]
Address(2001:db8::75b:cd15)
>>> # and they support slicing
>>> Network('2001:db8::/32')[100:110]
<ipv6thing._NetworkIterable object at 0x00000172144E8C70>
>>> list(Network('2001:db8::/32')[100:110])
[Address(2001:db8::64), Address(2001:db8::65), Address(2001:db8::66), Address(2001:db8::67), Address(2001:db8::68), Address(2001:db8::69), Address(2001:db8::6a), Address(2001:db8::6b), Address(2001:db8::6c), Address(2001:db8::6d)]
>>> # you can also check how many addresses are in a network, though it doesn't use python's len(), since  systems that can't return anything larger than sys.maxsize
>>> Network('2001:db8::/32').num_addresses
79228162514264337593543950336

>>> # you can control how addresses are formatted
>>> a = Address('2001:db8::abc')  
>>> f'{a:s}'  # s = short
'2001:db8::abc'
>>> f'{a:l}'  # l = long  
'2001:0db8:0000:0000:0000:0000:0000:0abc'
>>> f'{a:pc}'  # p = pad hextets, c = compress zeros
'2001:0db8::0abc'
>>> f'{a:tc}'  # t = trim hextets, c = compress zeroes
'2001:db8::abc'
>>> f'{a:te}'  # p = pad hextets, e = expand zeros
'2001:0db8:0000:0000:0000:0000:0000:0abc'
>>> f'{a:pe}'  # t = trim hextets, e = expand zeros
'2001:db8:0:0:0:0:0:abc'
>>> # these all work anywhere else format specifiers are accepted
>>> '{:l}'.format(a)
'2001:0db8:0000:0000:0000:0000:0000:0abc'
>>> # and they all work on networks as well
>>> n = Network('2001:db8::/32')
>>> f'{n:l}'
'2001:0db8:0000:0000:0000:0000:0000:0000/32'
```


