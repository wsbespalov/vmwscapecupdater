import os
import re
import os
import bz2
import enum
import gzip
import zipfile
import requests
from io import BytesIO
from datetime import datetime
from xml.sax import make_parser
from dateutil.parser import parse as parse_datetime
from xml.sax.handler import ContentHandler
from django.utils import timezone
from django.db import transaction

LOCAL_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODIFICATION_CLEAR = 0
MODIFICATION_NEW = 1
MODIFICATION_MODIFIED = 2

from .models import VULNERABILITY_CAPEC as CAPEC


class CAPECConfig(object):
    drop_core_table = True
    debug = True
    http_ignore_certs = False
    proxy = ""
    source = "http://capec.mitre.org/data/xml/capec_v2.6.xml"
    file_storage_root = 'media'
    capec_file = 'capec.xml'


class TextMessages(enum.Enum):
    ok = "ok"
    error = "error"
    created = "created"
    updated = "updated"
    skipped = "skipped"
    exception = "exception"
    complete = "Complete"
    make_parser = "Make parser"
    parse_data = "Parse data"
    set_status = "Set status"
    capec_updated = "CAPEC updated"
    download_file ="Download file"
    cant_download_file = "Cant get CAPEC file"


class CAPECHandler(ContentHandler):
    
    def __init__(self):
        self.capec = []
        self.Attack_Pattern_Catalog_tag = False
        self.Attack_Patterns_tag = False
        self.Attack_Pattern_tag = False
        self.Description_tag = False
        self.Summary_tag = False
        self.Text_tag = False
        self.Attack_Prerequisites_tag = False
        self.Attack_Prerequisite_tag = False
        self.Solutions_and_Mitigations_tag = False
        self.Solution_or_Mitigation_tag = False
        self.Related_Weaknesses_tag = False
        self.Related_Weakness_tag = False
        self.CWE_ID_tag = False

        self.tag = False

        self.id = ""
        self.name = ""

        self.Summary_ch = ""
        self.Attack_Prerequisite_ch = ""
        self.Solution_or_Mitigation_ch = ""
        self.CWE_ID_ch = ""

        self.Summary = []
        self.Attack_Prerequisite = []
        self.Solution_or_Mitigation = []
        self.Related_Weakness = []

    def startElement(self, name, attrs):

        if name == 'capec:Attack_Pattern_Catalog':
            self.Attack_Pattern_Catalog_tag = True
        if name == 'capec:Attack_Patterns' and self.Attack_Pattern_Catalog_tag:
            self.Attack_Patterns_tag = True
        if name == 'capec:Attack_Pattern' and self.Attack_Patterns_tag:
            self.Attack_Pattern_tag = True

        if self.Attack_Pattern_tag:
            self.tag = name
            if self.tag == 'capec:Attack_Pattern':
                self.id = attrs.getValue('ID')
                self.name = attrs.getValue('Name')

            if self.tag == 'capec:Description':
                self.Description_tag = True
            if name == 'capec:Summary' and self.Description_tag:
                self.Summary_tag = True
            if name == 'capec:Text' and self.Summary_tag:
                self.Text_tag = True
                self.Summary_ch = ""

            if self.tag == 'capec:Attack_Prerequisites':
                self.Attack_Prerequisites_tag = True
            if name == 'capec:Attack_Prerequisite' and \
                    self.Attack_Prerequisites_tag:
                self.Attack_Prerequisite_tag = True
            if name == 'capec:Text' and self.Attack_Prerequisite_tag:
                self.Text_tag = True
                self.Attack_Prerequisite_ch = ""

            if self.tag == 'capec:Solutions_and_Mitigations':
                self.Solutions_and_Mitigations_tag = True
            if name == 'capec:Solution_or_Mitigation' and \
                    self.Solutions_and_Mitigations_tag:
                self.Solution_or_Mitigation_tag = True
            if name == 'capec:Text' and self.Solution_or_Mitigation_tag:
                self.Text_tag = True
                self.Solution_or_Mitigation_ch = ""

            if self.tag == 'capec:Related_Weaknesses':
                self.Related_Weaknesses_tag = True
            if name == 'capec:Related_Weakness' and \
                    self.Related_Weaknesses_tag:
                self.Related_Weakness_tag = True
            if name == 'capec:CWE_ID' and self.Related_Weakness_tag:
                self.CWE_ID_tag = True
                self.CWE_ID_ch = ""

    def characters(self, ch):
        if self.Text_tag:
            if self.Summary_tag:
                self.Summary_ch += ch
            elif self.Attack_Prerequisite_tag:
                self.Attack_Prerequisite_ch += ch
            elif self.Solution_or_Mitigation_tag:
                self.Solution_or_Mitigation_ch += ch
        elif self.CWE_ID_tag:
            self.CWE_ID_ch += ch

    def endElement(self, name):
        if name == 'capec:Summary':
            if self.Summary_ch != "":
                self.Summary_ch = ""
            self.Summary_tag = False
        if name == 'capec:Attack_Prerequisite':
            if self.Attack_Prerequisite_ch != "":
                self.Attack_Prerequisite.append(
                    self.Attack_Prerequisite_ch.rstrip())
            self.Attack_Prerequisite_tag = False
        if name == 'capec:Solution_or_Mitigation':
            if self.Solution_or_Mitigation_ch != "":
                self.Solution_or_Mitigation.append(
                    self.Solution_or_Mitigation_ch.rstrip())
            self.Solution_or_Mitigation_tag = False
        if name == 'capec:Related_Weakness':
            if self.CWE_ID_ch != "":
                self.Related_Weakness.append(self.CWE_ID_ch.rstrip())
            self.Related_Weakness_tag = False

        if name == 'capec:Description':
            self.Description_tag = False
        if name == 'capec:Attack_Prerequisites':
            self.Attack_Prerequisites_tag = False
        if name == 'capec:Solutions_and_Mitigations':
            self.Solutions_and_Mitigations_tag = False
        if name == 'capec:Related_Weaknesses':
            self.Related_Weaknesses_tag = False

        if name == 'capec:Text':
            if self.Summary_tag:
                self.Summary.append(self.Summary_ch.rstrip())
            self.Text_tag = False
        if name == 'capec:CWE_ID':
            self.CWE_ID_tag = False
        if name == 'capec:Attack_Pattern':
            self.capec.append({
                'name': self.name,
                'id': self.id,
                'summary': '\n'.join(self.Summary),
                'prerequisites': '\n'.join(self.Attack_Prerequisite),
                'solutions': '\n'.join(self.Solution_or_Mitigation),
                'related_weakness': self.Related_Weakness})
            self.Summary = []
            self.Attack_Prerequisite = []
            self.Solution_or_Mitigation = []
            self.Related_Weakness = []

            self.Attack_Pattern_tag = False
        if name == 'capec:Attack_Patterns':
            self.Attack_Patterns_tag = False
        if name == 'capec:Attack_Pattern_Catalog':
            self.Attack_Pattern_Catalog_tag = False


def print_debug(message):
    if CAPECConfig.debug:
        print(message)


class CAPECController:

    ##########################################################################

    @staticmethod
    def make_answer(
        status=TextMessages.error.value,
        message=TextMessages.error.value,
        capec_cnt_before=0,
        capec_cnt_after=0,
        new_cnt=0,
        modified_cnt=0
    ):
        return dict(
            vulnerability=dict(count_before=capec_cnt_before, count_after=capec_cnt_after),
            vulnerability_new=dict(count=new_cnt),
            vulnerability_modified=dict(count=modified_cnt),
            status=status,
            message=message)

    ##########################################################################

    def stats(self):
        return 'ok stats'

    ##########################################################################
    
    def update(self):
        if CAPECConfig.drop_core_table:
            self.clear_capec_table()
        self.clear_all_marks()
        count_before = self.count_capec()
        print_debug(TextMessages.make_parser.value)
        parser = make_parser()
        capec_handler = CAPECHandler()
        parser.setContentHandler(capec_handler)
        print_debug(TextMessages.download_file.value)
        file_path, success, last_modified, size, fmt = self.upload_file()
        if success and file_path != "":
            f, success, message = self.read_file(file_path)
            if success and f is not None:
                print_debug(TextMessages.parse_data.value)
                parser.parse(f)
                count = 1
                for capec in capec_handler.capec:
                    capec['capec_id'] = 'CAPEC-{}'.format(capec['id'])
                    print_debug('processing CAPEC # {} with ID: {}'.format(count, capec["capec_id"]))
                    related_weakness = capec.get("related_weakness", [])
                    if related_weakness:
                        for index, value in enumerate(related_weakness):
                            related_weakness[index] = "CWE-{}".format(value)
                    capec["related_weakness"] = related_weakness
                    self.process_capec(capec)
                    count += 1
                count_after = self.count_capec()
                self.set_status(dict(name="capec", count=count_after, updated=last_modified, status="updated"))
        print_debug(TextMessages.complete.value)
        return self.make_answer(
            status=TextMessages.error.value,
            message=TextMessages.error.value,
            capec_cnt_before=0,
            capec_cnt_after=0,
            new_cnt=0,
            modified_cnt=0)

    ##########################################################################
    
    @staticmethod
    def upload_file():
        file_path = ''
        size = 0
        fmt = 'undefined'
        last_modified = datetime.utcnow()
        if not os.path.isdir(os.path.join(LOCAL_BASE_DIR, CAPECConfig.file_storage_root)):
            os.mkdir(os.path.join(LOCAL_BASE_DIR, CAPECConfig.file_storage_root))
        try:
            file_path = os.path.join(os.path.join(LOCAL_BASE_DIR, CAPECConfig.file_storage_root), CAPECConfig.capec_file)
            head = requests.head(CAPECConfig.source)
            content_type = head.headers.get('Content-Type')

            if 'gzip' in content_type:
                fmt = 'gzip'
            elif 'bzip2' in content_type:
                fmt = 'bzip2'
            elif 'zip' in content_type:
                fmt = 'zip'

            size = int(head.headers.get('Content-Length', 0))
            last_modified_text = head.headers.get('Last-Modified', '')
            last_modified = parse_datetime(last_modified_text)

            print('size: {}'.format(size))
            print('last: {}'.format(last_modified_text))
            print('format: {}'.format(fmt))

            file = requests.get(CAPECConfig.source, stream=True)

            with open(file_path, 'wb') as f:
                for chunk in file:
                    f.write(chunk)

            return file_path, True, last_modified, size, fmt
        except Exception as ex:
            print('[-] Got an exception: {}'.format(ex))
        return None, False, last_modified, size, fmt

    ##########################################################################

    @staticmethod
    def read_file(getfile):
        data = None
        if os.path.exists(getfile):
            print('file exists')
            if os.path.isfile(getfile):
                print('file is a file')
                with open(getfile, 'rb') as fp:
                    data = BytesIO(fp.read())
                    return data, True, 'raw file opened'
        return None, False, 'error with file read or unpack'


    ##########################################################################

    @staticmethod
    def set_status(status):
        print(TextMessages.set_status.value)
        print(status)

    ##########################################################################

    @staticmethod
    @transaction.atomic
    def clear_capec_table():
        for capec in CAPEC.objects.all().iterator():
            capec.delete()

    @staticmethod
    def clear_all_marks():
        return CAPEC.objects.select_for_update().all().update(modification=MODIFICATION_CLEAR)

    @staticmethod
    def clear_only_new_marks():
        return CAPEC.objects.select_for_update().filter(modification=MODIFICATION_NEW).update(modification=MODIFICATION_CLEAR)

    @staticmethod
    def clear_only_modified_marks():
        return CAPEC.objects.select_for_update().filter(modification=MODIFICATION_MODIFIED).update(modification=MODIFICATION_CLEAR)

    @staticmethod
    @transaction.atomic
    def count_capec():
        return CAPEC.objects.count()

    @staticmethod
    @transaction.atomic
    def count_capec_new():
        return CAPEC.objects.filter(modification=MODIFICATION_NEW).count()

    @staticmethod
    @transaction.atomic
    def count_capec_modified():
        return CAPEC.objects.filter(modification=MODIFICATION_MODIFIED).count()

    @staticmethod
    @transaction.atomic
    def get_all_new():
        return CAPEC.objects.filter(modification=MODIFICATION_NEW)

    @staticmethod
    @transaction.atomic
    def get_all_modified():
        return CAPEC.objects.filter(modification=MODIFICATION_MODIFIED)

    @staticmethod
    @transaction.atomic
    def get_capec_by_capec_id(capec_id):
        return CAPEC.objects.filter(capec_id=capec_id).first()

    @staticmethod
    def mark_capec_as_new_by_capec_id(capec_id):
        return CAPEC.objects.select_for_update().filter(capec_id=capec_id).update(modification=MODIFICATION_NEW)

    @staticmethod
    def mark_capec_as_modified_by_capec_id(capec_id):
        return CAPEC.objects.select_for_update().filter(capec_id=capec_id).update(modification=MODIFICATION_MODIFIED)

    def process_capec(self, incoming):
        capec = CAPEC.objects.filter(capec_id=incoming.get("capec_id", -1)).first()
        if capec is None:
            self.create_capec(incoming)
            return TextMessages.created.value
        if self.is_capec_changed(capec, incoming):
            self.update_capec(incoming)
            return TextMessages.updated.value
        return TextMessages.skipped.value
        
    @staticmethod
    def create_capec(capec):
        vulnerability = CAPEC.objects.filter(capec_id=capec.get("capec_id", -1)).first()
        if vulnerability is None:
            return CAPEC.objects.create(
                capec_id=capec["capec_id"],
                name=capec["name"],
                summary=capec["summary"],
                prerequisites=capec["prerequisites"],
                solutions=capec["solutions"],
                related_weakness=capec["related_weakness"],
                modification=MODIFICATION_NEW
            )

    @staticmethod
    def update_capec(capec):
        return CAPEC.objects.select_for_update().filter(capec_id=capec.get("capec_id", -1)).update(
            name=capec["name"],
            summary=capec["summary"],
            prerequisites=capec["prerequisites"],
            solutions=capec["solutions"],
            related_weakness=capec["related_weakness"],
            modification=MODIFICATION_MODIFIED)

    @staticmethod
    def is_capec_changed(old, incoming):
        if old.name != incoming["name"] or \
            old.summary != incoming["summary"] or \
            old.prerequisites != incoming["prerequisites"] or \
            old.solutions != incoming["solutions"] or\
            old.related_weakness != incoming["related_weakness"]:
            return True
        return False