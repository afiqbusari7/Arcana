from lxml import etree
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view


# Function to output event logs to xml file
def to_lxml(record_xml):
    parser = etree.XMLParser(recover=True)
    return etree.fromstring(record_xml, parser=parser)


# Function to read and write event logs
def xml_records(filename):
    with Evtx(filename) as evtx:
        for xml, record in evtx_file_xml_view(evtx.get_file_header()):
            try:
                yield to_lxml(xml), None
            except etree.XMLSyntaxError as e:
                yield xml, e


# Function to identify the information within parent tag
def get_child(node, tag, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    return node.find("%s%s" % (ns, tag))
