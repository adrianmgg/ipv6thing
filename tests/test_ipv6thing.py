from unittest import TestCase
from ipv6thing import Address

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

    def test_address_int_arithmetic(self) -> None:
        from operator import add, sub
        for lhs, op, rhs, should_be in [
            (Address('2001:db8::4'), add, 1, Address('2001:db8::5')),
            (Address('2001:db8::5'), add, -1, Address('2001:db8::4')),
            (1, add, Address('2001:db8::4'), Address('2001:db8::5')),
            (-1, add, Address('2001:db8::5'), Address('2001:db8::4')),
            (Address('2001:db8::4'), sub, -1, Address('2001:db8::5')),
            (Address('2001:db8::5'), sub, 1, Address('2001:db8::4')),
        ]:
            with self.subTest(lhs=lhs, rhs=rhs, op=op.__name__):
                self.assertEqual(op(lhs, rhs), should_be)
        # TODO check the ones that should fail too
