import os
import sys
import json
import zlib
import diskcache

baseDir = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
sys.path.append(baseDir)

CACHE_FOLDER = '/diskcache'
CWE_FOLDER = '/cwe'
TAG = u'cwe'

if not os.path.exists(os.path.join(baseDir, CACHE_FOLDER + CWE_FOLDER)):
    LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] Create folder for diskcache')
    os.makedirs(os.path.join(baseDir, CACHE_FOLDER + CWE_FOLDER))


# DequeDiskCache = diskcache.Deque()

class DequeDiskCache(diskcache.Deque):
	def __init__(self, compress_level=1, **kwargs):
		self.compress_level = compress_level
		super(DequeDiskCache, self).__init__(**kwargs)
	def compress_data(self, x):
		if isinstance(x, dict):
			xbytes = json.dumps(x).encode('utf-8')
		else:
			xbytes = str(x).encode('utf-8')
		return zlib.compress(xbytes, self.compress_level)
	def decompress_data(self, x):
		if isinstance(x, bytes):
			return zlib.decompress(x)
		return x
	def append(self, x, compressed=True):
		if compressed:
			return super(DequeDiskCache, self).append(self.compress_data(x))
		return super(DequeDiskCache, self).append(x)
	def appendleft(self, x, compressed=True):
		if compressed:
			return super(DequeDiskCache, self).appendleft(self.compress_data(x))
		return super(DequeDiskCache, self).appendleft(x)
	def clear(self):
		return super(DequeDiskCache, self).clear()
	def copy(self):
		return super(DequeDiskCache, self).copy()
	def count(self, x, compressed=True):
		if compressed:
			return super(DequeDiskCache, self).count(self.compress_data(x))
		return super(DequeDiskCache, self).count(x)
	def extend(self, it, compressed=True):
		if compressed:
			return super(DequeDiskCache, self).extend([self.compress_data(i) for i in it])
		return super(DequeDiskCache, self).extend(it)
	def extendleft(self, it, compressed=True):
		if compressed:
			return super(DequeDiskCache, self).extendleft([self.compress_data(i) for i in it])
		return super(DequeDiskCache, self).extendleft(it)
	def index(self, x, start, stop, compressed=True):
		if compressed:
			try:
				result = super(DequeDiskCache, self).index(self.compress_data(x), start, stop)
			except ValueError as ve:
				result = -1
		else:
			try:
				result = super(DequeDiskCache, self).index(x, start, stop)
			except ValueError as ve:
				result = -1
		return result
	def insert(self, position, x, compressed=True):
		if compressed:
			return super(DequeDiskCache, self).insert(position, self.compress_data(x))
		return super(DequeDiskCache, self).insert(position, x)
	def pop(self, compressed=True):
		if compressed:
			try:
				result = super(DequeDiskCache, self).pop()
				result = self.decompress_data(result)
			except IndexError as ie:
				result = None
		else:
			try:
				result = super(DequeDiskCache, self).pop()
			except IndexError as ie:
				result = None
		return result
	def popleft(self):
		if compressed:
			try:
				result = super(DequeDiskCache, self).popleft()
				result = self.decompress_data(result)
			except IndexError as ie:
				result = None
		else:
			try:
				result = super(DequeDiskCache, self).popleft()
			except IndexError as ie:
				result = None
		return result
	def remove(self, x, compressed=True):
		if compressed:
			return super(DequeDiskCache, self).remove(self.compress_data(x))
		return super(DequeDiskCache, self).remove(x)
	def reverse(self):
		return super(DequeDiskCache, self).reverse()
	def rotate(self, n=1):
		return super(DequeDiskCache, self).rotate(n)

# dd = DequeDiskCache()
# dd.append('this is the string', compressed=False)
# dd.append({'message': 'this is a JSON'}, compressed=False)

# print(len(dd))
# print(dd.index({'message': 'this is a JSON'}, 0, len(dd), compressed=False))

# print(dd.pop(compressed=True))
# print(dd.pop(compressed=True))
