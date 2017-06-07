"""
Test Suite for urlrequests2
"""

import unittest
import urequests2


class BaseCase(unittest.TestCase):
    """
    Base Unit Test Case
    """
    is_unit = True

    def setUp(self):
        pass

    def tearDown(self):
        pass


class StatusCodeTests(BaseCase):
    def test_404(self):
        # Ensure we get the correct Exception on a 404 Not Found
        self.assertRaises(urequests2.HTTPNotFound, urequests2.get,
                          'http://google.com/404')

    def test_500(self):
        self.assertRaises(urequests2.HTTPInternalError, urequests2.post,
                          'http://www.mplsart.com/api/posts?spork=true')

    def test_200(self):
        # Base case of testing a 200
        result = urequests2.get('http://showroommpls.com/visual-artists/')
        self.assertEquals(result.status_code, 200)


class ConnectionCodeTests(BaseCase):
    """ Tests Around Socket Failure Handling """
    def test_bad_domain(self):
        # Test to ensure that an invalid domain throws our URLError rather than internal socket err
        # TODO: Mock out actual socket connection so as not to do IO in tests

        try:
            result = urequests2.get('http://notarealdomainxx111.x/api/derp/')
            self.fail("Expected test to fail. Instead received result: %s" % result)
        except urequests2.URLError, e:
            expected_err = "<urlopen error [Errno 8] nodename nor servname provided, or not known>"
            self.assertEquals(str(e), expected_err)
