'''
Created on Jul 31, 2013

'''

#from ruleparser.data import *
from ruleparser.parser_checkpoint import *
import os, sys, traceback, time, mynetaddr
from collections import defaultdict
from utils.utils import * # @UnusedWildImport
import ruleparser.model as model1
from marshaller import xml_marshaller
    
from marshaller.xml_marshaller import *


class topology_inference(object):
    '''
    classdocs
    '''
    
    
def print_collection1 (title, collection):
    print "<--- "+title+" ---" 
    for o in collection:
        print(o)
         
    print "--->" 
 
def print_networks1():
    for n in model1.networks.itervalues():
       print n.ip.cidr

def print_firewall1():
    for n in model1.firewalls.itervalues():
      for x in n.interfaces:
           print x._primary_ipn
       
def print_nodes1():
#    print_collection1("Nodes", model1.hosts.values())
    for n in model1.hosts.itervalues():
        for x in n.interfaces:
            print x._primary_ipn.ip

firewall_adj=defaultdict(list)
def firewall_connectivity():
    for fw in model1.firewalls.itervalues():
        for x in fw.interfaces:
            for n in model1.networks.itervalues():
               if x._primary_ipn == n.ip:
                 # print x._primary_ipn, n.ip
                  firewall_adj[x._primary_ipn].append(n.ip) 
        
node_adj=defaultdict(list) 
def node_connectivity():
    for nd in model1.hosts.itervalues():
        for x in nd.interfaces:
            for n in model1.networks.itervalues():
                if x._primary_ipn.ip in n.ip.cidr:
                #    print x._primary_ipn, n.ip.ip, n.ip
                    node_adj[x._primary_ipn].append(n.ip)
                    
def print_node_adj():
    print "node adj"
    for item in node_adj:
        print item, node_adj[item]
        
def print_firewall_adj():
    print "firewall adj"
    for item in firewall_adj:
        print item, firewall_adj[item]        
                           
#print "node begins"                    
#print_nodes1()
#print "net begins"
#print_networks1() 
#print "firewall begins"
#print_firewall1()
#print "node_con begins"                  
node_connectivity()
#firewall_connectivity()
#print_node_adj() 
#print_firewall_adj()
#print "fire_con begins"    
firewall_connectivity()    

print TopoXMLMarshaller.to_Topo_XML()  
def __init__(self):
        '''
        Constructor
        '''
        #pass
   #     print TopoXMLMarshaller.to_Topo_XML() 
   
   
   30 sept
   '''
 Export data model to XML
'''
import mynetaddr
from ruleparser.model import * # @UnusedWildImport
from xml.etree import ElementTree as ET
from utils.utils import * # @UnusedWildImport
from ruleparser.confparser import * # @UnusedWildImport
import ruleparser.model as model1


#===============================================================================
# Topology XML Export
#===============================================================================
class TopoXMLMarshaller:
    TopoDTD = """ <?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE Topology [ 
<!ELEMENT Topology (Network*, Host*, Switch*, Firewall*, Tunnel*)>
<!ATTLIST Topology isEncrypted (true|false) #REQUIRED>

<!ELEMENT Network (Description)>
<!ATTLIST Network name CDATA #REQUIRED>
<!ATTLIST Network isCompletelyConnected (true|false) #REQUIRED>
<!ATTLIST Network netAddress CDATA #REQUIRED>
<!ATTLIST Network netMask CDATA #REQUIRED>

<!ELEMENT Host (Description, IPAddress+, NodeRef*)>
<!ATTLIST Host name CDATA #REQUIRED>
<!ATTLIST Host accessParameters CDATA #REQUIRED>

<!ELEMENT Switch (Description, IPAddress, NodeRef*)>
<!ATTLIST Switch name CDATA #REQUIRED>
<!ATTLIST Switch mode CDATA #IMPLIED>

<!ELEMENT Firewall (Description, IPAddress+, NodeRef*)>
<!ATTLIST Firewall name CDATA #REQUIRED>
<!ATTLIST Firewall accessParameters CDATA #REQUIRED>
<!ATTLIST Firewall NAT CDATA #REQUIRED>

<!ELEMENT NodeRef EMPTY>
<!ATTLIST NodeRef name CDATA #REQUIRED>

<!ELEMENT IPAddress EMPTY>
<!ATTLIST IPAddress ipAddress CDATA #REQUIRED>

<!ELEMENT Tunnel (Description, IPAddress+, NodeRef+)>
<!ATTLIST Tunnel encryption CDATA #IMPLIED>

<!ELEMENT Description (#PCDATA)>
]>
"""
    @staticmethod
    def to_Topo_XML():
        out = TopoXMLMarshaller.TopoDTD
        out += "<Topology isEncrypted = ""false"">"
        
        for n in shared.model.networks:
       #     out += str(n.ip.cidr)
            out += "\n" + TopoXMLMarshaller.marshal_network(shared.model.networks[n])
        #
        for nd in shared.model.hosts:
            out += "\n" + TopoXMLMarshaller.marshal_node(shared.model.hosts[nd])   
      
        for fw in shared.model.firewalls:
            out += "\n" + TopoXMLMarshaller.marshal_firewall(shared.model.firewalls[fw])       
        out += "\n</Topology>\n"      
        return out   
          
    @staticmethod
    def marshal_node(self):
        '''
        @return: a string listing the node attributes in XML format matching topology DTD
        '''
    #    if not type(self) == HOST:
     #       sys.stderr.write("\n<Topo XML Marshaller <ERROR>> Invalid Node object1.") 
        node = ET.Element("Host")
      #  node.set("id", n.nid)
        for x in self.interfaces:
            node.set("name", x.primary_ipn.ip.format())
            node.set("accessParameters", "None")
        
            description = ET.SubElement(node, "Description")
            description.text = str(self.desc) + " " + str(x.primary_ipn.ip.format())
            #description.text=self.desc
       
        
      #  node.set("type", n.device_type)
        #    node.set("Description", self.desc)
            IPAddress = ET.SubElement(node, "IPAddress")
            IPAddress.set("ipAddress", x.primary_ipn.ip.format())
            for n in self.nets.itervalues():
                NodeRef = ET.SubElement(node, "NodeRef")
                NodeRef.set("name", x.primary_ipn.ip.format())
        #for iface in n.interfaces:
            # @todo: complete
        #    intf = ET.SubElement(node, "Interface")            
        return ET.tostring(node, encoding="us-ascii", method="xml")
        

#    @staticmethod
#    def marshal_node(self):
        '''
        @return: a string listing the node attributes in XML format matching topology DTD
        '''
  #      if not type(self) == Node:
   #         sys.stderr.write("\n<Topo XML Marshaller <ERROR>> Invalid Node object.") 
 #       node = ET.Element("Host")
      #  node.set("id", n.nid)
  #      for x in self.interfaces:
    #        node.set("name", x.primary_ipn.ip.format())
   #         node.set("accessParameters", "None")
        
     #       description = ET.SubElement(node, "Description")
      #      description.text=self.desc + str( x.primary_ipn.ip.format())
           # description.text=self.desc
       
        
      #  node.set("type", n.device_type)
       #     node.set("Description", self.desc)
        #    IPAddress = ET.SubElement(node, "IPAddress")
         #   IPAddress.set("ipAddress", x.primary_ipn.ip.format())
        #    for n in x.nets.itervalues():
        #        NodeRef = ET.SubElement(node, "NodeRef")
        #        NodeRef.set("name", x.primary_ipn.ip.format())
        #for iface in n.interfaces:
            # @todo: complete
        #    intf = ET.SubElement(node, "Interface")            
       # return ET.tostring(node, encoding="us-ascii", method="xml")
    
    @staticmethod
    def marshal_firewall(self):
        '''
        @return: a string listing the node attributes in XML format matching topology DTD
        '''
        if not type(self) == Firewall:
            sys.stderr.write("\n<Topo XML Marshaller <ERROR>> Invalid Node object.") 
        node = ET.Element("Firewall")
      #  node.set("id", n.nid)
        description = ET.SubElement(node, "Description")
        description.text= self.desc 
           # description.text=self.desc
        for x in self.interfaces:
            node.set("name", x.name)
            
            node.set("name", x.primary_ipn.ip.format())
            node.set("accessParameters", "None")
        
            #description = ET.SubElement(node, "Description")
            #description.text= str(self.desc) + str( x.primary_ipn.ip.format())
           # description.text=self.desc
       
        
        #    node.set("type", n.device_type)
            #node.set("Description", self.desc)
            IPAddress = ET.SubElement(node, "IPAddress")
            IPAddress.set("ipAddress", x.primary_ipn.ip.format())
        for x in self.interfaces:
            for n in self.nets.itervalues():
                NodeRef = ET.SubElement(node, "NodeRef")
                NodeRef.set("name", str(x.primary_ipn.cidr))
        #for iface in n.interfaces:
            # @todo: complete
        #    intf = ET.SubElement(node, "Interface")            
        return ET.tostring(node, encoding="us-ascii", method="xml")
    
    @staticmethod
    def marshal_interface(self):
        '''
        @todo implement export to XML
        @return: a string listing the interface attributes in XML format
        '''        
        iface = ET.Element("Interface")
        iface.set("id", self.iface_id)
        iface.set("name",self.name)
        iface.set("dev_id", self.dev_id)
        iface.set("dev_type", self.dev_type)
        iface.set("ip", self.ip.format)
        iface.set("description", self.desc)
        iface.set("sec_level", self.sec_level)
        iface.set("network", self.net)
        return ET.tostring(iface, encoding="us-ascii", method="xml")
    
    @staticmethod
    def marshal_network(self):
        '''
        @todo implement export to XML
        @return: a string listing the network attributes in XML format
        '''
        network = ET.Element("Network")
        network.set("name", str(self.ipn))
        network.set("isCompletelyConnected", "true")
        network.set("netAddress", str(self.ipn.ip.format))
        network.set("netMask", str(self.ipn))
        #network.set("group", self.group)
        
        #network.set("netmask", "mask")
        
        description = ET.SubElement(network, "Description")
        description.text=self.desc
        return ET.tostring(network, encoding="us-ascii", method="xml")
    
    

    
#===============================================================================
# Ruleset XML Export
#===============================================================================
class RulesetXMLMarshaller:

    RulesetDTD = """<?xml version='1.0' encoding='us-ascii'?>
      
      <!DOCTYPE RuleSetCollection [
        
      <!ELEMENT RuleSetCollection   (RuleSet*)>
        
      <!ELEMENT RuleSet   (Description, Attributes*, IPInterface*, Zone*, Route*, NetworkGroup*, ServiceObject*, ServiceGroup*, ICMPGroup*, ProtocolGroup*, AccessList*)>
      <!ATTLIST RuleSet name CDATA #REQUIRED>

      <!ELEMENT Attributes EMPTY)>
      <!ATTLIST Attributes vendor CDATA #IMPLIED>
      <!ATTLIST Attributes model CDATA #IMPLIED>
      <!ATTLIST Attributes sameSecurityLevelTrafficAllowed (true | false) #IMPLIED>
      <!ATTLIST Attributes outboundVPNBypassAcls (true | false) #IMPLIED>
      <!ATTLIST Attributes inboundVPNBypassAcls (true | false) #IMPLIED>
     
      <!ELEMENT IPInterface EMPTY>
      <!ATTLIST IPInterface name CDATA #REQUIRED>
      <!ATTLIST IPInterface address CDATA #REQUIRED>
      <!ATTLIST IPInterface netmask CDATA #REQUIRED>
      <!ATTLIST IPInterface security-level CDATA #IMPLIED>
    
      <!ELEMENT Zone (Interface+)>
      <!ATTLIST Zone name CDATA #REQUIRED>
      <!ELEMENT Interface EMPTY>
      <!ATTLIST Interface name CDATA #REQUIRED>
    
      <!ELEMENT Route (AddressBlock)>
      <!ATTLIST Route interfaceName CDATA #REQUIRED>
      <!ATTLIST Route gateway CDATA #REQUIRED>
      <!ATTLIST Route distance CDATA #REQUIRED>
      <!ATTLIST Route type (standard|tunneled) #IMPLIED>
    
      <!ELEMENT NetworkGroup (Description*, AddressBlock+)>
      <!ATTLIST NetworkGroup name CDATA #REQUIRED>
      <!ELEMENT AddressBlock EMPTY>
      <!ATTLIST AddressBlock NetAddress CDATA #REQUIRED>
      <!ATTLIST AddressBlock NetMask CDATA #REQUIRED>
    
      <!ELEMENT ServiceObject (Description*, PortRange*)>
      <!ATTLIST ServiceObject name CDATA #REQUIRED>
      <!ATTLIST ServiceObject protocol CDATA #REQUIRED>
    
      <!ELEMENT ServiceGroup (Description*, PortRange*, ServiceObject*)>
      <!ATTLIST ServiceGroup name CDATA #REQUIRED>
    
      <!ELEMENT PortRange EMPTY>
      <!ATTLIST PortRange protocol CDATA #REQUIRED>
      <!ATTLIST PortRange beginPort CDATA #REQUIRED>
      <!ATTLIST PortRange endPort CDATA #REQUIRED> 
      <!ATTLIST PortRange type (source|destination) #IMPLIED>
      
      <!ELEMENT ICMPGroup (Description*, ICMPType+)>
      <!ATTLIST ICMPGroup name CDATA #REQUIRED>
      <!ELEMENT ICMPType EMPTY>
      <!ATTLIST ICMPType type CDATA #REQUIRED>
      
      <!ELEMENT ProtocolGroup (Description*, ProtocolID+)>
      <!ATTLIST ProtocolGroup name CDATA #REQUIRED>
      <!ELEMENT ProtocolID EMPTY>
      <!ATTLIST ProtocolID protocol CDATA #REQUIRED>
      
      <!ELEMENT AccessList (Description*, AuthorizedUsers*, Rule*)>
      <!ATTLIST AccessList name CDATA #REQUIRED>
      <!ATTLIST AccessList incomingInterface CDATA #REQUIRED>
      <!ATTLIST AccessList incomingZone CDATA #REQUIRED>
      <!ATTLIST AccessList direction (in|out) #IMPLIED>
      <!ATTLIST AccessList ACLType (regular|aaa|vpn) #REQUIRED>
      <!ATTLIST AccessList remotePeer CDATA #IMPLIED>
      
      <!ELEMENT AuthorizedUsers (User*)>
      <!ATTLIST AuthorizedUsers aaaServerAddress CDATA #REQUIRED>
      <!ATTLIST AuthorizedUsers aaaServerProtocol CDATA #REQUIRED>
      
      <!ELEMENT User EMPTY>
      <!ATTLIST User name CDATA #REQUIRED>
      
      <!ELEMENT Rule (Description*, Source+, Destination+, Service*, PortRange*)>
      <!ATTLIST Rule name CDATA #REQUIRED>
      <!ATTLIST Rule action CDATA #REQUIRED>
      <!ATTLIST Rule enabled (true | false) #REQUIRED>
      <!ATTLIST Rule original CDATA #IMPLIED>
      <!ATTLIST Rule bidirectional (true | false) #IMPLIED>
      
      <!ELEMENT Source (#PCDATA)>      
      <!ELEMENT Destination (#PCDATA)>      
      <!ELEMENT Service (#PCDATA)>  
           
      <!ELEMENT Description (#PCDATA)>
      ]>
    """
    #@staticmethod
  #  def to_Topo_XML():
   #     out = TopoXMLMarshaller.TopoDTD
    #    out += "<Topology isEncrypted=false>"
        
     #   for n in model1.shared.model.networks.itervalues():
          #  out += str(n.ip.cidr)
      #      out += "\n" + TopoXMLMarshaller.marshal_network(n)
       # for nd in model1.hosts.itervalues():
        #    out += "\n" + TopoXMLMarshaller.marshal_node(nd)   
        #for fw in model1.firewalls.itervalues():
         #   out += "\n" + TopoXMLMarshaller.marshal_firewall(fw)       
        #out += "\n</Topology>\n"      
        #return out         
        

    @staticmethod
    def marshal_node(self):
        '''
        @return: a string listing the node attributes in XML format matching topology DTD
        '''
  #      if not type(self) == Node:
   #         sys.stderr.write("\n<Topo XML Marshaller <ERROR>> Invalid Node object.") 
        node = ET.Element("Host")
      #  node.set("id", n.nid)
        for x in self.interfaces:
            node.set("name", x.primary_ipn.ip.format())
            node.set("accessParameters", "None")
        
            description = ET.SubElement(node, "Description")
            description.text=self.desc + str( x.primary_ipn.ip.format())
           # description.text=self.desc
       
        
      #  node.set("type", n.device_type)
            node.set("Description", self.desc)
            IPAddress = ET.SubElement(node, "IPAddress")
            IPAddress.set("ipAddress", x.primary_ipn.ip.format())
            for n in x.nets.itervalues():
                NodeRef = ET.SubElement(node, "NodeRef")
                NodeRef.set("name", x.primary_ipn.ip.format())
        #for iface in n.interfaces:
            # @todo: complete
        #    intf = ET.SubElement(node, "Interface")            
        return ET.tostring(node, encoding="us-ascii", method="xml")
    
    @staticmethod
    def marshal_firewall(self):
        '''
        @return: a string listing the node attributes in XML format matching topology DTD
        '''
        if not type(self) == NodeType.FIREWALL:
            sys.stderr.write("\n<Topo XML Marshaller <ERROR>> Invalid Node object.") 
        node = ET.Element("Firewall")
      #  node.set("id", n.nid)
        for x in self.interfaces:
            node.set("name", x.name)
            
            #node.set("name", x.primary_ipn.ip.format())
           # node.set("accessParameters", "None")
        
            #description = ET.SubElement(node, "Description")
            #description.text=self.desc + str( x.primary_ipn.ip.format())
           # description.text=self.desc
       
        
      #  node.set("type", n.device_type)
            #node.set("Description", self.desc)
            IPAddress = ET.SubElement(node, "IPAddress")
            IPAddress.set("ipAddress", x.primary_ipn.ip.format())
        for x in self.interfaces:
            for n in x.nets.itervalues():
                NodeRef = ET.SubElement(node, "NodeRef")
                NodeRef.set("name", str(x.primary_ipn.cidr))
        #for iface in n.interfaces:
            # @todo: complete
        #    intf = ET.SubElement(node, "Interface")            
        return ET.tostring(node, encoding="us-ascii", method="xml")
    
    @staticmethod
    def marshal_interface(self):
        '''
        @todo implement export to XML
        @return: a string listing the interface attributes in XML format
        '''        
        iface = ET.Element("Interface")
        iface.set("id", self.iface_id)
        iface.set("name",self.name)
        iface.set("dev_id", self.dev_id)
        iface.set("dev_type", self.dev_type)
        iface.set("ip", self.ip.format)
        iface.set("description", self.desc)
        iface.set("sec_level", self.sec_level)
        iface.set("network", self.net)
        return ET.tostring(iface, encoding="us-ascii", method="xml")
    
    @staticmethod
    def marshal_network(self):
        '''
        @todo implement export to XML
        @return: a string listing the network attributes in XML format
        '''
        network = ET.Element("Network")
        network.set("name", str(self.ip.cidr))
        network.set("isCompletelyConnected", "True")
        network.set("netAddress", self.ip.ip.format())
        network.set("netMask", self.ip.netmask.format())
        #network.set("group", self.group)
        
        #network.set("netmask", "mask")
        
        description = ET.SubElement(network, "Description")
        description.text=self.desc
        return ET.tostring(network, encoding="us-ascii", method="xml")
    
    
 
    @staticmethod
    def to_ruleset_XML():
        '''
        Produce the full ruleset file as a string based on data present in the model
        '''
        out = RulesetXMLMarshaller.RulesetDTD
        out += "<RuleSetCollection>\n"
        # Add all global objects (if any)
        for type,obj_dict in shared.model.global_objects.iteritems():
            for obj in obj_dict.values():
                oxml = RulesetXMLMarshaller.marshal_object(obj, type)
                if oxml is not None:
                    out += "\n" + ET.tostring(oxml, encoding="us-ascii", method="xml")
                else:
                    sys.stderr.write("\n<Parser Model <ERROR>> Failed to serialize object "+obj.name)
        # Add all firewalls
        for fw in shared.model.firewalls.values():
            fwxml = RulesetXMLMarshaller.marshal_firewall(fw)
            if fwxml is not None:
               # out += "\n" + ET.tostring(fwxml, encoding="us-ascii", method="xml")
               out = "\n|" + "to hello"
            else:
                sys.stderr.write("\n<Parser Model <ERROR>> Failed to serialize firewall "+fw.name)
        out += "</RuleSetCollection>\n"         
        return out
    
    
    @staticmethod
    def marshal_object(obj):
        for case in switch(obj._class__):
            if case(Service):
                return(RulesetXMLMarshaller.marshal_service(obj))
            elif case(Protocol):
                return(RulesetXMLMarshaller.marshal_protocol(obj))
            elif case(ICMP_Type):
                return(RulesetXMLMarshaller.marshal_icmp_type(obj))
            else:
                return(RulesetXMLMarshaller.marshal_address(obj))
                
    @staticmethod
    def marshal_group(gobj, fw):
        '''
        @param gobj: Group object to be marshalled
        @param fw: parent firewall where this group is defined  
        @return: a ruleset XML element with the group attributes  
        '''
        if not gobj.name:    
            sys.stderr.write("\n<XML Marshalling <ERROR>> Invalid group without name")
        grp_xml = None
        for case in switch(gobj.type):
            # Marshal address group
            if case(GroupType.ADDRESS):                   
                grp_xml = ET.Element("NetworkGroup")
                objs = RulesetXMLMarshaller.resolve_group(gobj, GroupType.ADDRESS, fw.groups[GroupType.ADDRESS])
                for g in objs:
                    grp_xml.append(RulesetXMLMarshaller.marshal_object(g))
            # Marshal service group                     
            elif case(GroupType.SERVICE):   
                grp_xml = ET.Element("ServiceGroup")
                objs = RulesetXMLMarshaller.resolve_group(gobj, GroupType.SERVICE, fw.groups[GroupType.SERVICE])
                for g in objs:
                    grp_xml.append(RulesetXMLMarshaller.marshal_object(g))
            
            # Marshal protocol group
            elif case(GroupType.PROTOCOL):   
                grp_xml = ET.Element("ProtocolGroup")
                objs = RulesetXMLMarshaller.resolve_group(gobj, GroupType.PROTOCOL, fw.groups[GroupType.PROTOCOL])
                for g in objs:
                    grp_xml.append(RulesetXMLMarshaller.marshal_object(g))
            
            # Marshal ICMP type group
            elif case(GroupType.ICMP):   
                grp_xml = ET.Element("ICMPGroup")
                objs = RulesetXMLMarshaller.resolve_group(gobj, GroupType.ICMP, fw.groups[GroupType.ICMP])
                for g in objs:
                    grp_xml.append(RulesetXMLMarshaller.marshal_object(g))
            else:
                sys.stderr.write("\n<Parser Model <ERROR>> Invalid group %s with unknown type %s"%(gobj.name, gobj.type))
                return
        grp_xml.set("name", gobj.name)        
        if gobj.desc:
            desc = ET.SubElement(grp_xml, "Description")
            # Add group description
            desc.text = gobj.desc
        return grp_xml
    
    
    @staticmethod
    def marshal_acl(a):
        '''
        @return: a ruleset XML element with the provided ACL attributes 
        '''
        acl = ET.Element("AccessList")
        acl.set("name", a.name)
        # @todo: incomingInterface
        # @todo: incomingZone
        # @todo: direction
        # @todo: ACLType
        # @todo: remotePeer
        for r in a.rules:
            r_xml = RulesetXMLMarshaller.marshal_rule(r)
            if r_xml is not None:
                acl.append(r_xml)   
        if a.description:
            desc = ET.SubElement(a, "Description")
            # Add acl description
            desc.text = a.description
        return acl
    
    @staticmethod
    def marshal_rule(r):
        '''
        @return: a ruleset XML element with the provided rule attributes 
        @todo: add support for multiple sources, destinations and actions
        '''      
        rule = ET.Element("Rule")
        if not r.name or r.name == "NULL":
            # todo give arbitrary name to unamed rules
            sys.stderr.write(u"\n<XML Marshalling <WARNING>> Skip unnamed rule.")
            return
        else:
            rule.set("name", r.name)
        rule.set("action", r.action)
        rule.set("original", r.original)
        rule.set("bidirectional", "false")
        if r.description:
            rdesc = ET.SubElement(rule, "Description")
            # Add rule description
            rdesc.text = r.description
        # Add rule source(s)
        for src in r.sources:
            # Retrieve source node, adding prefix group: if matching known group
            #if not r.dev_id:
            #    sys.stderr.write(u"\n<XML Marshalling <ERROR>> Invalid rule with no parent device")
            #fw = firewalls[r.dev_id]
            # @todo search routers if no fw found matching this device id
            #if fw.
            rsrc = ET.SubElement(rule, "Source")
            rsrc.text = src
        # Add rule destination(s)
        for dst in r.destinations:
            rdst = ET.SubElement(rule, "Destination")
            rdst.text = dst
        # Add rule service(s)
        for svc in r.services:
            rsvc = ET.SubElement(rule, "Service")
            rsvc.text = svc            
        return rule
    
    @staticmethod
    def marshal_address(mbraddr):
        # Add member address/mask
        if type(mbraddr) == mynetaddr.IPAddress:
            mbrel = ET.Element("AddressBlock")                    
            mbrel.set("NetAddress",mbraddr.ip)                   
            mbrel.set("NetMask",mbraddr.netmask)
        # Member is not an address, search network objects and groups (@todo: and ranges)
        else:
            matched = False
            #- Search host list
            for v in shared.model.hosts.itervalues():
                if v.name == mbraddr:
                    matched = True
                    for intf in v.interfaces:
                        mbrel = ET.Element("AddressBlock")                     
                        mbrel.set("NetAddress",intf.primary_ipn.ip.format())                   
                        mbrel.set("NetMask","255.255.255.255")
                    break
                if matched:
                    break
            #- Search network list
            for v in shared.model.networks.itervalues():
                if v.name == mbraddr:
                    matched = True
                    mbrel = ET.Element("AddressBlock")                     
                    mbrel.set("NetAddress",v.ipn.ip.format())                   
                    mbrel.set("NetMask",v.ipn.netmask.format())
                    break
                if matched:
                    break
            #- Search address groups
            if not matched:
                net_grp = shared.model.global_groups[GroupType.ADDRESS][mbraddr]
                if net_grp:
                    # Resolve nested group members
                    net_grp_addrs = RulesetXMLMarshaller.resolve_net_group(net_grp, shared.model.hosts, shared.model.networks, None, shared.model.global_groups[GroupType.ADDRESS])
                    for addr in net_grp_addrs:
                        mbrel = ET.Element("AddressBlock")    
                        if type(addr) == mynetaddr.IPAddress:                 
                            mbrel.set("NetAddress",addr.format())                   
                            mbrel.set("NetMask","255.255.255.255")     
                        elif type(addr) == mynetaddr.IPNetwork:      
                            mbrel.set("NetAddress",addr.ip.format())                   
                            mbrel.set("NetMask",addr.netmask.format())      
        return mbrel
                            
    @staticmethod
    def marshal_service(svc):
        '''
        Write a service object attributes into XML format
        '''
        svc_xml = ET.Element("ServiceObject")
        svc_xml.set("name", svc.name)
        svc_xml.set("protocol", svc.protocol)    
        
        src_pr = ET.SubElement(svc_xml, "PortRange")
        src_pr.set("protocol", svc.protocol)
        if svc.src_ports._class__ == Range:
            src_pr.set("beginPort", svc.src_ports.tuple[0])
            src_pr.set("endPort", svc.src_ports.tuple[1])
        else: 
            src_pr.set("beginPort", svc.src_ports)
            src_pr.set("endPort", svc.src_ports)
        src_pr.set("type", "source")
        
        dst_pr = ET.SubElement(svc_xml, "PortRange")
        dst_pr.set("protocol", svc.protocol)
        if svc.dst_ports._class__ == Range:
            dst_pr.set("beginPort", svc.dst_ports.tuple[0])
            dst_pr.set("endPort", svc.dst_ports.tuple[1])
        else:
            dst_pr.set("beginPort", svc.dst_ports)
            dst_pr.set("endPort", svc.dst_ports)            
        dst_pr.set("type", "destination")
        return svc_xml
  
    @staticmethod
    def marshal_protocol(protobj):
        '''
        Write a protocol object attributes into XML format (as a protocol group)
        '''
        sub = ET.Element("ProtocolID")
        sub.set("protocol", protobj.id)                                                         
        return sub   
    
    @staticmethod
    def marshal_icmp_type(icmpobj):
        '''
        Write an icmp type object attributes into XML format (as an ICMP group)
        '''
        sub = ET.Element("ICMPType")
        sub.set("type", icmpobj.id)                                                         
        return sub   
    
    @staticmethod
    def resolve_net_group(net_grp, host_dict, net_dict, range_dict, grp_dict):
        '''
         Recursively scan the provided network group returning all nested groups 
         as list of IPAddress or IPNetwork objects 
         @param net_grp: group object to be resolved
         @param host_dict: 1x1 mapping (host_name x Host)
         @param net_dict: 1x1 mapping (network_name x Network object)
         @param range_dict: 1x1 mapping (range_name x Range object)
         @param grp_dict: 1x1 mapping (group_name x Group object)
         @return: group resolved (all subgroups replaced by their content)
         ''' 
        addrs = []
        for mbr in net_grp.members:
            if type(mbr) == mynetaddr.IPAddress or type(mbr) == mynetaddr.IPNetwork:
                addrs.append(mbr)
            else:
                if type(mbr) == str:
                    # Search host map      
                    if mbr in host_dict.keys():
                        for intf in host_dict[mbr].interfaces:
                            addrs.append(intf.ip)
                        continue
                    # Search network map
                    if mbr in net_dict.keys():
                        addrs.append(net_dict[mbr].ip)
                        continue
                    # @todo: search range map
                    # Search group map
                    addrs.append(RulesetXMLMarshaller.resolve_net_group(grp_dict[mbr]))
                elif type(mbr) == Host:
                    for intf in mbr.interfaces():
                        addrs.append(intf.ip)
                    continue
                elif type(mbr) == Network:
                    addrs.append(mbr.ip)
                    continue
                elif type(mbr) == Group:
                    addrs.append(RulesetXMLMarshaller.resolve_net_group(mbr))      
                                         
        return addrs            
    
    @staticmethod
    def resolve_group(grp_obj, grp_type, grp_dict):
        '''
         Recursively scan the provided group (other than network group)
         replacing all group names by their content 
         @param grp_obj: group object to be resolved
         @param grp_type: group type 
         @param grp_dict: 1x1 mapping (group_name x Group object)
         @return: group resolved (all subgroups replaced by their content)
         ''' 
        objs = []
        for o in grp_obj.members:
            if o._class__ in (Service, Protocol, ICMP_Type):
                objs.append(o)
            elif type(o) == str:
                # Search the group dict for a group with this name
                if o in grp_dict.keys():
                    g = grp_dict[o]
                    if g:
                        res = RulesetXMLMarshaller.resolve_group(g, grp_type, grp_dict)
                        for r in res:
                            objs.append(r)
                else:
                    if grp_obj.type == GroupType.ADDRESS:
                        objs.append(o)
                    else:
                        sys.stderr.write("\n<Parser Model <ERROR>> Group %s refers to unknown object %s"%(grp_obj.name, o))
            else:
                sys.stderr.write("\n<Parser Model <ERROR>> %s Group %s contains undefined object type %s"%(grp_type, grp_obj.name, o._class__))
        return objs


=====30 sept topo
==============
#from ruleparser.data import *
from netaddr import *
from netaddr.ip import cidr_merge
from ruleparser.parser_checkpoint import *
import os, sys, traceback, time, mynetaddr
from collections import defaultdict
from utils.utils import * # @UnusedWildImport
import ruleparser.model as model1
from shared import shared
from marshaller import xml_marshaller
from marshaller.xml_marshaller import *

node_adj = defaultdict(list) 
firewall_adj = defaultdict(list)


class topology_inference(object):
    '''
    classdocs
    '''
    
    def print_collection1 (self, title, collection):
        print "<--- "+title+" ---" 
        for o in collection:
            print(o)
         
        print "--->" 
    
    def interface_networks(self):
        print " interface_networks:"
        for nd in shared.model.hosts.values():
            for x in nd.interfaces:
           # for n in model1.shared.model.hosts.itervalues():
         #       if x.primary_ipn.ip in n.ip.cidr:
                print x.primary_ipn.ip
                print "============"
                print nd.nets[x.primary_ipn]
                print "--------------"
              #  for n in x.nets[]
               #     print "hhh"
                #    print n
                 #   print "--------------"    
                 
                    #x.nets[x.primary_ipn].append(n.ip)
                #
           #  ip_list = [ ip for ip in x.nets.itervalues()]
   # ip = IPNetwork('192.0.2.16/29')
  #  ip_list = [IPAddress('192.0.2.130'), IPAddress('10.0.0.1'), IPNetwork('192.0.2.128/28'), IPNetwork('192.0.3.0/24'), IPNetwork('192.0.2.0/24'), IPNetwork('fe80::/64'), IPAddress('::'), IPNetwork('172.24/12')]
   # ip_list = list(iter_iprange('192.0.2.1', '192.0.2.14'))
                print " merge"
                print cidr_merge(nd.nets[x.primary_ipn])
                    
    def print_hosts_networks(self):
        for nd in shared.model.hosts:
            for x in shared.model.shared.model.hosts[nd].interfaces:
                print x.primary_ipn.ip
                print "============"
                print x.nets[x.primary_ipn]
                print "--------------"
              # 
                print cidr_merge(x.nets[x.primary_ipn])
                     
    def print_networks1(self):
        for n in shared.model.networks:
            print shared.model.networks[n].ipn

    def print_firewall1(self):
        for n in shared.model.firewalls:
            for x in shared.model.firewalls[n].interfaces:
                print x.primary_ipn
       
    def print_nodes1(self):
#    print_collection1("Nodes", model1.shared.model.hosts.values())
        #for n in hosts.itervalues():
        for n in shared.model.hosts:    
            print "hi nodes"
            for x in shared.model.hosts[n].interfaces:
                print x.primary_ipn.ip

    #firewall_adj=defaultdict(list)
    def firewall_connectivity(self):
        
        print " firewall_connectivity:"
        for fw_id in shared.model.firewalls:
            fw = shared.model.firewalls[fw_id]
            for x in fw.interfaces:
                for n in shared.model.networks.values():
                    if x.primary_ipn == n.ipn:
                    #    print x.primary_ipn, networks[n].ipn
                        #x.nets[x.primary_ipn].append(networks[n].ipn)
                        fw.nets[x.primary_ipn].append(n.ipn)
                       
                        firewall_adj[x.primary_ipn].append(n.ipn) 
        
#node_adj=defaultdict(list) 
    def node_connectivity(self):
        print " node_connectivity:"
        for nd_id in shared.model.hosts:
            nd = shared.model.hosts[nd_id]
            for x in nd.interfaces:
                for n in shared.model.networks.values():
                  #  print "net host"
                   # print shared.model.networks[n].ipn, x.primary_ipn.ip   
                    if x.primary_ipn.ip in n.ipn:
                     #   print "net hosts"
                        nd.nets[x.primary_ipn].append(n.ipn)
                      #  print x.primary_ipn, shared.model.networks[n].ipn.ip, shared.model.networks[n].ipn
                     # node_adj[x.primary_ipn].append(n.ipn)
                    
    def print_node_adj(self):
        print "node adj"
        for item in node_adj:
            print item, node_adj[item]
        
    def print_firewall_adj(self):
        print "firewall adj"
        for item in firewall_adj:
            print item, firewall_adj[item] 
               
                          
    
  #  get_all_hosts(confparser)                    
   # print_nodes1()
#print "net begins"
#print_networks1() 
#print "firewall begins"
#print_firewall1()
#print "node_con begins"                  
   # node_connectivity()
#firewall_connectivity()
#print_node_adj() 
#print_firewall_adj()
#print "fire_con begins"    
    #firewall_connectivity()   
    #print "interface connectivity" 

    #print_interface_networks()
 
    #print TopoXMLMarshaller.to_Topo_XML()  
    
    def __init__(self):
        '''
        Constructor
        '''
       # print_nodes1(self)
       # self.conf = confparser()
      #  print "node begins"
     #   confparser.get_all_hosts(self.conf)
      
   #     print TopoXMLMarshaller.to_Topo_XML() 

        