import os
import sys
import time
import json
import zlib
from threading import Thread
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from datetime import datetime

baseDir = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
sys.path.append(baseDir)

from logger import LOGERR_IF_ENABLED, LOGINFO_IF_ENABLED
from utils import get_file, get_module_name, check_internet_connection
from settings import SETTINGS

from dskcache import DequeDiskCache as dc

SOURCE_MODULE = '[{0}] :: '.format(get_module_name(__file__))
PLUGIN_NAME = get_module_name(__file__)


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
            self.description_summary = self.description_summary + self.description_summary
            self.cwe[-1]['description_summary'] = self.description_summary.replace("\n", "")
        elif name == 'Weakness':
            self.weakness_tag = False


class UPDCWEThreadClass(Thread):
    def __init__(self, name, callback=None, callback_args=None, *args, **kwargs):
        target = kwargs.pop('target')
        super(UPDCWEThreadClass, self).__init__(target=self.target_with_callback, *args, **kwargs)
        self.callback = callback
        self.method = target
        LOGINFO_IF_ENABLED(SOURCE_MODULE, 'get {} args'.format(callback_args))
        self.callback_args = callback_args

    def target_with_callback(self):
        self.method()
        if self.callback is not None:
            self.callback(self.callback_args)

def job_for_cwe_updater():
    LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] Start CWE updater job')
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
                    dc.append(item)
                LOGINFO_IF_ENABLED(SOURCE_MODULE, "[===========================================================================]")
                LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] CWE update complete at: {}'.format(datetime.utcnow()))
                LOGINFO_IF_ENABLED(SOURCE_MODULE, "[===========================================================================]")
                return False
            else:
                LOGERR_IF_ENABLED(SOURCE_MODULE, '[-] There are some errors in server response: {}'.format(response))
                return False
        except Exception as ex:
            LOGERR_IF_ENABLED(SOURCE_MODULE, "Got exception during downloading CWE source: {0}".format(ex))
            return False
    else:
        LOGERR_IF_ENABLED(SOURCE_MODULE, '[-] No internet connection!')
        return False

def callback_for_cwe_updater_thread(args=[]):
    LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] Callback for CWE Updater complete job called with args: {}'.format(args))
    LOGINFO_IF_ENABLED(SOURCE_MODULE, '[+] Diskcache size is: {}'.format(len(dc)))

def start_cwe_updater_job(args):
    thr = UPDCWEThreadClass(
        name='UPDCWEThreadClass',
        target=job_for_cwe_updater,
        callback=callback_for_cwe_updater_thread,
        callback_args=args
        )
    thr.start()

############################




############################

def main(args):
    if len(args) == 0:
        args = []
        start_cwe_updater_job(args)
    else:
        if condition:
            pass
        else:
            pass
        pass


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))