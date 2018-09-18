import os
import sys
import abc
import time
import json
import zlib
import enum

baseDir = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
sys.path.append(baseDir)

from flask import Flask
from datetime import datetime
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from logger import LOGERR_IF_ENABLED, LOGINFO_IF_ENABLED
from utils import get_file, get_module_name, check_internet_connection
from settings import SETTINGS

from diskcache import Deque

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



class State(enum.Enum):
    start = 1
    pending = 2
    downloading = 3
    parsing = 4
    caching_local = 5
    caching_global = 6
    idle = 7



class CWEUpdater:
    """
    CWE Updater State Machine.
    Know its observers to Notify it.
    Any number of Observer objects may observe a subject.
    Send a notification to its observers when its state changes.
    """

    def __init__(self):
        self._observers = set()
        self._subject_state = None

    def attach(self, observer):
        observer._subject = self
        self._observers.add(observer)

    def detach(self, observer):
        observer._subject = None
        self._observers.discard(observer)

    def _notify(self):
        for observer in self._observers:
            observer.update(self._subject_state)

    @property
    def subject_state(self):
        return self._subject_state

    @subject_state.setter
    def subject_state(self, arg):
        self._subject_state = arg
        self._notify()

    def start(self):
        self.subject_state = State.start.value
        time.sleep(1)
        self.subject_state = State.downloading.value
        time.sleep(1)
        self.subject_state = State.parsing.value
        time.sleep(1)
        self.subject_state = State.idle.value


class Observer(metaclass=abc.ABCMeta):
    """
    Define an updating interface for objects that should be notified of
    changes in a subject.
    """

    def __init__(self):
        self._subject = None
        self._observer_state = None

    @abc.abstractmethod
    def update(self, arg):
        pass


class CWEUpdaterLogObserver(Observer):
    """
    Implement the Observer updating interface to keep its state consistent with the subject's.
    Store state that should stay consistent with the subject's.
    Notify User by LOGGER.
    """

    def update(self, state):
        self._observer_state = state
        LOGINFO_IF_ENABLED(SOURCE_MODULE, '[s] Set state as: {}'.format(state))


class CWEUpdaterRedisObserver(Observer):
    """
    Implement the Observer updating interface to keep its state consistent with the subject's.
    Store state that should stay consistent with the subject's.
    Notify User by REDIS.
    """

    def update(self, state):
        self._observer_state = state
        print('*** Set Redis state: {}'.format(state))


def main():
    cwe_updater_machine = CWEUpdater()

    cwe_updater_log_observer = CWEUpdaterLogObserver()
    cwe_updater_machine.attach(cwe_updater_log_observer)

    cwe_updater_redis_observer = CWEUpdaterRedisObserver()
    cwe_updater_machine.attach(cwe_updater_redis_observer)

    cwe_updater_machine.subject_state = State.idle.value
    cwe_updater_machine.start()


if __name__ == '__main__':
    main()

