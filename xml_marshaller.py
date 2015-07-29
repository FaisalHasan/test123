'''
 Export data model to XML
'''
import mynetaddr
from ruleparser.model import * # @UnusedWildImport
from xml.etree import ElementTree as ET
from utils.utils import * # @UnusedWildImport
from ruleparser.confparser import * # @UnusedWildImport


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
        out += "<Topology isEncrypted=false>"
        
        for n in model1.networks.itervalues():
            print n
            TopoXMLMarshaller.marshal_network(n)
        out += "</Topology>\n"      
        return out         
        

    @staticmethod
    def marshal_node(n):
        '''
        @return: a string listing the node attributes in XML format matching topology DTD
        '''
        if not type(n) == Node:
            sys.stderr.write("\n<Topo XML Marshaller <ERROR>> Invalid Node object.") 
        node = ET.Element("Node")
        node.set("id", n.nid)
        node.set("name",n.name)
        node.set("type", n.device_type)
        node.set("Description", n.desc)
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
        network.set("name", self.name)
        network.set("isCompletelyConnected", "True")
        network.set("netAddress", self.ip.ip.format())
        network.set("netMask", self.ip.netmask.format())
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
    
      <!ELEMENT NetworkGroup (Description, AddressBlock+)>
      <!ATTLIST NetworkGroup name CDATA #REQUIRED>
      <!ELEMENT AddressBlock EMPTY>
      <!ATTLIST AddressBlock NetAddress CDATA #REQUIRED>
      <!ATTLIST AddressBlock NetMask CDATA #REQUIRED>
    
      <!ELEMENT ServiceObject (Description, PortRange*)>
      <!ATTLIST ServiceObject name CDATA #REQUIRED>
      <!ATTLIST ServiceObject protocol CDATA #REQUIRED>
    
      <!ELEMENT ServiceGroup (Description, PortRange*, ServiceObject*)>
      <!ATTLIST ServiceGroup name CDATA #REQUIRED>
    
      <!ELEMENT PortRange EMPTY>
      <!ATTLIST PortRange protocol CDATA #REQUIRED>
      <!ATTLIST PortRange beginPort CDATA #REQUIRED>
      <!ATTLIST PortRange endPort CDATA #REQUIRED> 
      <!ATTLIST PortRange type (source|destination) #IMPLIED>
      
      <!ELEMENT ICMPGroup (Description, ICMPType+)>
      <!ATTLIST ICMPGroup name CDATA #REQUIRED>
      <!ELEMENT ICMPType EMPTY>
      <!ATTLIST ICMPType type CDATA #REQUIRED>
      
      <!ELEMENT ProtocolGroup (Description, ProtocolID+)>
      <!ATTLIST ProtocolGroup name CDATA #REQUIRED>
      <!ELEMENT ProtocolID EMPTY>
      <!ATTLIST ProtocolID protocol CDATA #REQUIRED>
      
      <!ELEMENT AccessList (Description, AuthorizedUsers*, Rule*)>
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
      
      <!ELEMENT Rule      (Description, Source+, Destination+, Service*, PortRange*)>
      <!ATTLIST Rule name CDATA #REQUIRED>
      <!ATTLIST Rule action CDATA #REQUIRED>
      <!ATTLIST Rule enabled (true | false) #REQUIRED>
      <!ATTLIST Rule audit CDATA #REQUIRED>
      <!ATTLIST Rule testMode (true | false) #REQUIRED>
      <!ATTLIST Rule original CDATA #IMPLIED>
      <!ATTLIST Rule ruleNegated (true | false) #REQUIRED>
      <!ATTLIST Rule allowTcpConnectInit (true | false) #REQUIRED>      
      
      <!ELEMENT Source (#PCDATA)>      
      <!ELEMENT Destination (#PCDATA)>      
      <!ELEMENT Service (#PCDATA)>  
           
      <!ELEMENT Description (#PCDATA)>
      ]>
    """
 
    @staticmethod
    def to_ruleset_XML():
        '''
        Produce the full ruleset file as a string based on data present in the model
        '''
        out = RulesetXMLMarshaller.RulesetDTD
        out += "<RuleSetCollection>\n"
        # Add all global objects (if any)
        for type,obj_dict in global_objects.iteritems():
            for obj in obj_dict.values():
                oxml = RulesetXMLMarshaller.marshal_object(obj, type)
                if oxml is not None:
                    out += "\n"+ET.tostring(oxml, encoding="us-ascii", method="xml")
                else:
                    sys.stderr.write("\n<Parser Model <ERROR>> Failed to serialize object "+obj.name)
        # Add all firewalls
        for fw in firewalls.values():
            fwxml = RulesetXMLMarshaller.marshal_firewall(fw)
            if fwxml is not None:
                out += "\n"+ET.tostring(fwxml, encoding="us-ascii", method="xml")
            else:
                sys.stderr.write("\n<Parser Model <ERROR>> Failed to serialize firewall "+fw.name)
        out += "</RuleSetCollection>\n"         
        return out
    
    @staticmethod
    def marshal_node(self):     
        '''
        @return: a ruleset element with the node attributes
        '''
        ifacexml = ET.Element("IPInterface")
        ifacexml.set("name",self.name)
        if len(self.interfaces) > 1:          
            sys.stderr.write("\n<Ruleset XML Marshalling <ERROR>> Invalid interface with multiple addresses")
        elif len(self.interfaces) < 1:          
            sys.stderr.write("\n<Ruleset XML Marshalling <ERROR>> Invalid interface with no address")
        else:
            if type(self.interfaces[0]) == mynetaddr.IPNetwork:
                ifacexml.set("address",self.interfaces[0].net.ip.format)    
                ifacexml.set("netmask",self.interfaces[0].net.netmask.format)
                return ifacexml
            else:                      
                sys.stderr.write("\n<Ruleset XML Marshalling <ERROR>> Invalid interface address. Should be of type IPNetwork")
    
    @staticmethod
    def marshal_object(obj):
        for case in switch(obj.__class__):
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
        grp = None
        for case in switch(gobj.type):
            # Marshal address group
            if case(GroupType.ADDRESS):                
                grp = ET.Element("NetworkGroup")        
                objs = RulesetXMLMarshaller.resolve_group(gobj, GroupType.ADDRESS, fw.groups[GroupType.ADDRESS])
                for g in objs:
                    grp.append(RulesetXMLMarshaller.marshal_object(g))   
            # Marshal service group                     
            elif case(GroupType.SERVICE):
                grp = ET.Element("ServiceGroup")
                objs = RulesetXMLMarshaller.resolve_group(gobj, GroupType.SERVICE, fw.groups[GroupType.SERVICE])
                for g in objs:
                    grp.append(RulesetXMLMarshaller.marshal_object(g))   
            
            # Marshal protocol group
            elif case(GroupType.PROTOCOL):
                grp = ET.Element("ProtocolGroup")
                objs = RulesetXMLMarshaller.resolve_group(gobj, GroupType.PROTOCOL, fw.groups[GroupType.PROTOCOL])
                for g in objs:
                    grp.append(RulesetXMLMarshaller.marshal_object(g))   
            
            # Marshal ICMP type group
            elif case(GroupType.ICMP):
                grp = ET.Element("ICMPGroup")
                objs = RulesetXMLMarshaller.resolve_group(gobj, GroupType.ICMP, fw.groups[GroupType.ICMP])
                for g in objs:
                    grp.append(RulesetXMLMarshaller.marshal_object(g))   
            else:
                sys.stderr.write("\n<Parser Model <ERROR>> Invalid group %s with unknown type %s"%(gobj.name, gobj.type))
                return
        grp.set("name", gobj.name)
        return grp
    
    @staticmethod
    def marshal_firewall(fw):
        '''
        @todo implement export to XML
        @return: a string listing the firewall/cluster attributes in XML format
        '''
        # Cluster members are not marshalled, only the cluster is
        if fw.is_cluster_member():
            return None
        fw_xml = ET.Element("RuleSet")
        fw_xml.set("name", fw.name)
        # Add interfaces        
        for iface in fw.interfaces:
            iface_xml = RulesetXMLMarshaller.marshal_interface(iface)
            if iface_xml is not None:
                fw_xml.append(iface_xml)
        '''
        # Add service objects defined in this firewall     
        for sobj in fw.services:
            if sobj is not None:
                svc_el = RulesetXMLMarshaller.marshal_service(sobj)
                if svc_el:
                    fw_xml.append(svc_el)
        # Add protocol objects defined in this firewall     
        for pobj in fw.protocols:
            if pobj is not None:
                proto_el = RulesetXMLMarshaller.marshal_protocol(pobj)
                if proto_el:
                    fw_xml.append(proto_el)
        # Add icmp objects defined in this firewall     
        for icmp_obj in fw.icmp_types:
            if icmp_obj is not None:
                icmp_el = RulesetXMLMarshaller.marshal_icmp_type(icmp_obj)
                if icmp_el:
                    fw_xml.append(icmp_el)
        '''
        # Add groups  
        for k,v in fw.groups.iteritems():
            for grp in v.values():
                grp_el = RulesetXMLMarshaller.marshal_group(grp, fw)
                if grp_el is not None:
                    fw_xml.append(grp_el)
        # Add rules
        for a in fw.acls:
            fw_xml.append(RulesetXMLMarshaller.marshal_acl(a))
        return fw_xml
        #fw.set("acls", "True")
        #fw.set("cluster_members", self._cluster_membersNetwork.set("netAddress", self._ip)
    
    @staticmethod
    def marshal_interface(intf):
        '''
        @return: a string listing the interface attributes in XML format
        @todo: support multiple ips in DTD
        '''        
        iface = ET.Element("IPInterface")
        iface.set("name",intf.name)
        iface.set("address", intf.primary_ipn.ip.format())
        iface.set("netmask", intf.primary_ipn.netmask.format())
        if intf.sec_level is not None:
            iface.set("security-level", intf.sec_level)
        return iface
    
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
        rule.set("audit", "false")
        rule.set("testMode", "false")
        rule.set("original", r.original)
        rule.set("ruleNegated", "false")
        rule.set("allowTcpConnectInit", "false")
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
            for v in hosts.itervalues():
                if v.name == mbraddr:
                    matched = True
                    for intf in v.interfaces:
                        mbrel = ET.Element("AddressBlock")                     
                        mbrel.set("NetAddress",intf.ip.ip.format())                   
                        mbrel.set("NetMask","255.255.255.255")
                    break
                if matched:
                    break
            #- Search network list
            for v in networks.itervalues():
                if v.name == mbraddr:
                    matched = True
                    mbrel = ET.Element("AddressBlock")                     
                    mbrel.set("NetAddress",v.ip.ip.format())                   
                    mbrel.set("NetMask",v.ip.netmask.format())
                    break
                if matched:
                    break
            #- Search address groups
            if not matched:
                net_grp = global_groups[GroupType.ADDRESS][mbraddr]
                if net_grp:
                    # Resolve nested group members
                    net_grp_addrs = RulesetXMLMarshaller.resolve_net_group(net_grp, hosts, networks, None, global_groups[GroupType.ADDRESS])
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
        if svc.src_ports.__class__ == Range:
            src_pr.set("beginPort", svc.src_ports.tuple[0])
            src_pr.set("endPort", svc.src_ports.tuple[1])
        else: 
            src_pr.set("beginPort", svc.src_ports)
            src_pr.set("endPort", svc.src_ports)
        src_pr.set("type", "source")
        
        dst_pr = ET.SubElement(svc_xml, "PortRange")
        dst_pr.set("protocol", svc.protocol)
        if svc.dst_ports.__class__ == Range:
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
        proto_xml = ET.Element("ProtocolGroup")
        proto_xml.set("name", protobj.name)
        sub = ET.SubElement(proto_xml, "ProtocolID")
        sub.set("protocol", protobj.id)                                                         
        return proto_xml   
    
    @staticmethod
    def marshal_icmp_type(icmpobj):
        '''
        Write an icmp type object attributes into XML format (as an ICMP group)
        '''
        icmp_xml = ET.Element("ICMPGroup")
        icmp_xml.set("name", icmpobj.name)
        sub = ET.SubElement(icmp_xml, "ICMPType")
        sub.set("type", icmpobj.id)                                                         
        return icmp_xml   
    
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
            if o.__class__ in (Service, Protocol, ICMP_Type):
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
                        sys.stderr.write("\n<Parser Model <ERROR>> Group %s refers to unknown object %s"%(grp_obj.name, o))
            else:
                sys.stderr.write("\n<Parser Model <ERROR>> %s Group %s contains undefined object type %s"%(grp_type, grp_obj.name, o.__class__))
                
        return objs

