from unittest import TestCase
from ipv6thing import Address, Network

class AddressTests(TestCase):
    def test_valid_addresses(self) -> None:
        for addr, should_be in [
            ('ABCD:EF01:2345:6789:ABCD:EF01:2345:6789', 0xABCD_EF01_2345_6789_ABCD_EF01_2345_6789),
            ('2001:DB8:0:0:8:800:200C:417A', 0x2001_0DB8_0000_0000_0008_0800_200C_417A),
            ('2001:DB8::8:800:200C:417A', 0x2001_0DB8_0000_0000_0008_0800_200C_417A),
            ('FF01::101', 0xFF01_0000_0000_0000_0000_0000_0000_0101),
            ('::1', 0x0000_0000_0000_0000_0000_0000_0000_0001),
            ('::', 0x0000_0000_0000_0000_0000_0000_0000_0000),
            ('1::', 0x0001_0000_0000_0000_0000_0000_0000_0000),
            ('1000::', 0x1000_0000_0000_0000_0000_0000_0000_0000),
        ]:
            with self.subTest(addr):
                self.assertEqual(int(Address(addr)), should_be)

    def test_invalid_addresses(self) -> None:
        for addr, exc_type, message in [
            ('a::b::c', ValueError, "address can only have one '::'"),
            ('abcde::', ValueError, 'hextet must be 4 digits or less'),
            ('01234::', ValueError, 'hextet must be 4 digits or less'),
        ]:
            with self.subTest(addr):
                with self.assertRaises(exc_type) as exc_cm:
                    Address(addr)
                exc = exc_cm.exception
                if message is not None:
                    self.assertEqual(str(exc), message)

    def test_address_int_arithmetic_valid(self) -> None:
        from operator import add, sub
        for lhs, op, rhs, should_be in [
            (Address('2001:db8::4'), add,  1, Address('2001:db8::5')),
            (Address('2001:db8::5'), add, -1, Address('2001:db8::4')),
            (Address('2001:db8::4'), sub, -1, Address('2001:db8::5')),
            (Address('2001:db8::5'), sub,  1, Address('2001:db8::4')),
        ]:
            with self.subTest(op=op.__name__, lhs=lhs, rhs=rhs):
                self.assertEqual(op(lhs, rhs), should_be)

    def test_address_int_arithmetic_invalid(self) -> None:
        from operator import add, sub
        for lhs, op, rhs, exc_type, exc_msg in [
            (0, add, Address('2001:db8::4'), TypeError, r'^unsupported operand type\(s\)'),
            (0, sub, Address('2001:db8::5'), TypeError, r'^unsupported operand type\(s\)'),
            (Address('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'), add,  1, ValueError, r'^address out of range$'),
            (Address('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'), sub, -1, ValueError, r'^address out of range$'),
            (Address('::'),                                      add, -1, ValueError, r'^address out of range$'),
            (Address('::'),                                      sub,  1, ValueError, r'^address out of range$'),
        ]:
            with self.subTest(op=op.__name__, lhs=lhs, rhs=rhs):
                with self.assertRaisesRegex(exc_type, exc_msg):
                    op(lhs, rhs)

    def test_network_parsing(self) -> None:
        for args, addr, prefix_len in [
            ([Address('2001:DB8::'), 32],                     Address('2001:DB8'), 32),
            ([0x2001_0db8_0000_0000_0000_0000_0000_0000, 32], Address('2001:DB8'), 32),
            (['2001:DB8::', 32],                              Address('2001:DB8'), 32),
            (['2001:DB8::/32'],                               Address('2001:DB8'), 32),
        ]:
            with self.subTest(args):
                net = Network(*args)
                self.assertEqual(net.base_address, addr)
                self.assertEqual(net.prefix_len, prefix_len)

    def test_address_format(self) -> None:
        for addr, format_spec, should_be in [
            ('::',  's',  '::'),
            ('::',  'l',  '0000:0000:0000:0000:0000:0000:0000:0000'),
            ('::',  'pc', '::'),
            ('::',  'tc', '::'),
            ('::',  'pe', '0000:0000:0000:0000:0000:0000:0000:0000'),
            ('::',  'te', '0:0:0:0:0:0:0:0'),

            ('1::', 's',  '1::'),
            ('1::', 'l',  '0001:0000:0000:0000:0000:0000:0000:0000'),
            ('1::', 'pc', '0001::'),
            ('1::', 'tc', '1::'),
            ('1::', 'pe', '0001:0000:0000:0000:0000:0000:0000:0000'),
            ('1::', 'te', '1:0:0:0:0:0:0:0'),

            ('::1',  's',  '::1'),
            ('::1',  'l',  '0000:0000:0000:0000:0000:0000:0000:0001'),
            ('::1',  'pc', '::0001'),
            ('::1',  'tc', '::1'),
            ('::1',  'pe', '0000:0000:0000:0000:0000:0000:0000:0001'),
            ('::1',  'te', '0:0:0:0:0:0:0:1'),
        ]:
            with self.subTest(addr=addr, format_spec=format_spec):
                formatted = f'{{:{format_spec}}}'.format(Address(addr))
                self.assertEqual(formatted, should_be)
