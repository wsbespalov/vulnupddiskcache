import os
import sys
import time
import json
import zlib
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from datetime import datetime

baseDir = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
sys.path.append(baseDir)

from logger import LOGERR_IF_ENABLED, LOGINFO_IF_ENABLED
from utils import get_file, get_module_name, check_internet_connection
from settings import SETTINGS

SOURCE_MODULE = '[{0}] :: '.format(get_module_name(__file__))
PLUGIN_NAME = get_module_name(__file__)

CACHE_FOLDER = '/diskcache'
CWE_FOLDER = '/cwe'
TAG = u'cwe'

if not os.path.exists(os.path.join(baseDir, CACHE_FOLDER + CWE_FOLDER)):
    os.makedirs(os.path.join(baseDir, CACHE_FOLDER + CWE_FOLDER))

import diskcache


class JSONDisk(diskcache.Disk):
    def __init__(self, directory, compress_level=1, **kwargs):
        self.compress_level = compress_level
        super(JSONDisk, self).__init__(directory, **kwargs)

    def put(self, key):
        json_bytes = json.dumps(key).encode('utf-8')
        data = zlib.compress(json_bytes, self.compress_level)
        return super(JSONDisk, self).put(data)

    def get(self, key, raw):
        data = super(JSONDisk, self).get(key, raw)
        return json.loads(zlib.decompress(data).decode('utf-8'))

    def store(self, value, read):
        if not read:
            json_bytes = json.dumps(value).encode('utf-8')
            value = zlib.compress(json_bytes, self.compress_level)
        return super(JSONDisk, self).store(value, read)

    def fetch(self, mode, filename, value, read):
        data = super(JSONDisk, self).fetch(mode, filename, value, read)
        if not read:
            data = json.loads(zlib.decompress(data).decode('utf-8'))
        return data


# dc = diskcache.Cache(CACHE_FOLDER + CWE_FOLDER, disk=JSONDisk, disk_compress_level=6)
dc = diskcache.Deque()


class CWEHandler(ContentHandler):
    def __init__(self):
        self.cwe = []
        self.description_summary_tag = False
        self.weakness_tag = False

    def startElement(self, name, attrs):
        if name == 'Weakness':
            self.weakness_tag = True
            self.statement = ""
            self.weaknesses = attrs.get('Weakness_Abstraction')
            self.name = attrs.get('Name')
            self.idname = attrs.get('ID')
            self.status = attrs.get('Status')
            self.cwe.append({
                'name': self.name,
                'id': self.idname,
                'status': self.status,
                'weaknesses': self.weaknesses})
        elif name == 'Description_Summary' and self.weakness_tag:
            self.description_summary_tag = True
            self.description_summary = ""

    def characters(self, ch):
        if self.description_summary_tag:
            self.description_summary += ch.replace("       ", "")

    def endElement(self, name):
        if name == 'Description_Summary' and self.weakness_tag:
            self.description_summary_tag = False
            self.description_summary = self.description_summary + \
                                       self.description_summary
            self.cwe[-1]['description_summary'] = \
                self.description_summary.replace("\n", "")
        elif name == 'Weakness':
            self.weakness_tag = False

class CWEUpdater(object):

    def __init__(self, argv):
        pass

    def update_cwe(self):
        parsed_items= []
        if check_internet_connection():
            parser = make_parser()
            cwe_handler = CWEHandler()
            parser.setContentHandler(cwe_handler)
            source = SETTINGS.get("cwe", {}).get("source", "http://cwe.mitre.org/data/xml/cwec_v2.8.xml.zip")
            try:
                LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] Start downloading file')
                data, response = get_file(getfile=source)
                if 'error' not in response:
                    LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] Start parsing CWE data')
                    parser.parse(data)
                    LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] Complete parsing CWE data')
                    for cwe in cwe_handler.cwe:
                        cwe['description_summary'] = cwe['description_summary'].replace("\t\t\t\t\t", " ")
                        item = {'tag': 'cwe', 'state':'parsed', 'data': cwe}
                        parsed_items.append(item)
                    LOGINFO_IF_ENABLED(SOURCE_MODULE, "[===========================================================================]")
                    LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] CWE update complete at:'.format(datetime.utcnow()))
                    LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+]     Processed:   {}'.format(len(parsed_items)))
                    LOGINFO_IF_ENABLED(SOURCE_MODULE, "[===========================================================================]")
                    return parsed_items
                else:
                    LOGERR_IF_ENABLED(SOURCE_MODULE, '[-] There are some errors in server response: {}'.format(response))
            except Exception as ex:
                LOGERR_IF_ENABLED(SOURCE_MODULE, "Got exception during downloading CWE source: {0}".format(ex))
                return []
        else:
            LOGERR_IF_ENABLED(SOURCE_MODULE, '[-] No internet connection!')
            return []

    def job(self):
        LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] Start job')
        parsed_items = self.update_cwe()
        if len(parsed_items) != 0:

            result = True
            return True
        else:
            LOGINFO_IF_ENABLED(SOURCE_MODULE, '[-] Parser returns empty list, nothing to process.')
            result = False
        LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] Complete job')
        return result




from threading import Thread


class UPDCWE(Thread):
    def __init__(self, name, callback=None, callback_args=None, *args, **kwargs):
        target = kwargs.pop('target')
        super(UPDCWE, self).__init__(target=self.target_with_callback, *args, **kwargs)
        self.callback = callback
        self.method = target
        self.callback_args = callback_args

    def target_with_callback(self):
        self.method()
        if self.callback is not None:
            self.callback(*self.callback_args)


def jonb():
    import time
    dc.append({'message': 'test'})
    dc.append({'message': 'test2'})
    dc.append({'message': 'test3'})
    time.sleep(3)

def cb(args):
    print('callback with args: {}'.format(args))
    for d in list(dc):
        print(d)

def test2():
    print('start test2')
    thr = UPDCWE(
        name='test2',
        target=jonb,
        callback=cb,
        callback_args=('test 2 args',)
        )
    thr.start()


class SetThread(Thread):
    def __init__(self, name):
        Thread.__init__(self)
        self.name = name

    def run(self):
        dc.append({'message': 'test'})
        dc.append({'message': 'test2'})
        dc.append({'message': 'test3'})

class GetThread(Thread):
    def __init__(self, name):
        Thread.__init__(self)
        self.name = name

    def run(self):
        import time
        time.sleep(3)
        for d in list(dc):
            print(d)


def test():
    th1 = SetThread('setThread')
    th1.start()
    th2 = GetThread('getThread')
    th2.start()

def main(argv):
    if argv:
        if argv[0] == 'test':
            test()
        elif argv[0] == 'test2':
            test2()
    else:
        cweUpdater = CWEUpdater(argv)
        cweUpdater.job()

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))