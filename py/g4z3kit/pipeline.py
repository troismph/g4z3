import unittest


class Pipeline(object):

    def __init__(self, it):
        self._it = it
        self._funcs = []

    def append(self, *funcs):
        for func in funcs:
            self._funcs.append(func)
        return self

    def __iter__(self):
        self._itt = self._it.__iter__()
        return self

    def __next__(self):
        r = self._itt.__next__()
        for f in self._funcs:
            r = f(r)
        return r


class TestPipeline(unittest.TestCase):

    def test_basic(self):
        dat = [x for x in range(10)]
        dat_expect_0 = [0 for x in dat]
        dat_expect_1 = [x * 2 for x in dat]
        dat_expect_2 = [x * 2 * 3 * 4 for x in dat]

        data_original = [x for x in Pipeline(dat)]
        data0 = [x for x in Pipeline(dat).append(lambda x: 0)]
        data1 = [x for x in Pipeline(dat).append(lambda x: x * 2)]
        data2 = [x for x in Pipeline(dat).append(
            lambda x: x * 2,
            lambda x: x * 3,
            lambda x: x * 4
        )]

        self.assertEqual(dat, data_original)
        self.assertEqual(dat_expect_0, data0)
        self.assertEqual(dat_expect_1, data1)
        self.assertEqual(dat_expect_2, data2)


if __name__ == "__main__":
    unittest.main()
