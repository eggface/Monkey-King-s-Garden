#it is a plugins for e7Sniffer2.rb
#including, 
# Netconf request, as string
# Response parse, as method and return out put
$MESSAGE_ID_END = 999

#If not E7-2, E7-20, E3, E5, End of Netconf

$MESSAGE_ID_ACTIVE_CARD = 100
$MESSAGE_ID_RUNNING_VER = 101 # all
$MESSAGE_ID_DHCP_LEASES = 102 # all
$MESSAGE_ID_SHOW_PPPOE_SESSIONS = 106 # all
# E3 and E5, End of Netconf

$MESSAGE_ID_HAS_DISC_ONT = 104 #E7-2 E7-20
$MESSAGE_ID_ONT_WITH_RGWAN = 105 #E7-2 E7-20
# E7-20, End of Netconf

$MESSAGE_ID_HAS_VDSL48C = 103 #E7-2

$ENTRANCE_ID = $MESSAGE_ID_ACTIVE_CARD 

class NCPlugins
    @@device_object = nil

    def self.get_plugin msgid
        case msgid
        when $MESSAGE_ID_ACTIVE_CARD
            NCPluginCard.instance
        when $MESSAGE_ID_RUNNING_VER 
            NCPluginVer.instance
        when $MESSAGE_ID_DHCP_LEASES
            NCPluginDhcpLeases.instance
        when $MESSAGE_ID_SHOW_PPPOE_SESSIONS
            NCPluginShowPppoeSessions.instance
        when $MESSAGE_ID_HAS_VDSL48C
            NCPluginHasVDSL48C.instance
        when $MESSAGE_ID_HAS_DISC_ONT
            NCPluginHasDiscOnt.instance
        when $MESSAGE_ID_ONT_WITH_RGWAN
            NCPluginOntWithRgWan.instance
        else
            puts "Undefined msgid: #{msgid}"
        end
    end

    def self.get_close_str
        "<rpc message-id='#{$MESSAGE_ID_END}' xmlns='urn:ietf:params:xml:ns:netconf:base:1.0'><close-session/></rpc>"
    end

    #parse message id with given message body
    def self.parse_msgid string
        if string.size > 0 and string.include?("message-id")
            return string.match(/message-id=\"(\d+)\"/).to_a[1].to_i
        else
            return nil
        end
    end

    def self.set_device device_object
        @@device_object = device_object
    end

    def self.get_device
        @@device_object
    end

    def initialize
    end

    def get_next_id
        @nextid
    end

    def set_req string 
        #return req directly if no overwrite
        get_req
    end

    def get_req 
        #@input
        #if it is the last, return nil. EOF should be sent
    end

    #to be overwritten by children
    def parse string
        #implemented in sub classes
        if string.size > 0 and string.include?("rpc-error")
            puts "[RPC Error] #{string}" 
            false
        else
            true
        end
    end

    #parse string and return next sent string
    def parse_send string
        result_for_next = parse(string)
        puts "[parse_send] result for next: #{result_for_next}"

        msgid = get_next_id
        puts "[parse_send] next id is: #{msgid}"

        if !msgid
            puts "[parse_send] next id is nil"
            return NCPlugins.get_close_str
        else
            plugin = NCPlugins.get_plugin(msgid)
            plugin.set_req(result_for_next)
        end
    end
end

class NCPluginCard < NCPlugins
    @@instance = NCPluginCard.new
    def self.instance
        @@instance
    end

    def get_next_id
        $MESSAGE_ID_RUNNING_VER
    end

    def get_req
        "<rpc message-id='#{$MESSAGE_ID_ACTIVE_CARD}' nodename='' timeout='35000'> <get> <filter type='subtree'> <top> <object> <type>System</type> <id /> </object> </top> </filter> </get> </rpc>"
    end

    #<active-card> <type>Card</type> <id> <shelf>1</shelf> <card>1</card> </id> </active-card>
    def parse string
        return nil unless super
        #puts "string to be parsed is #{string}"
        if string.size > 0 and string.include?("active-card")
            string.match(/<active-card>(.*?)<\/active-card>/).to_a[1]
        elsif string.size > 0 and string.match(/<shelf-type>(.*?)48(.*?)<\/shelf-type>/)
            "<type>Card</type> <id> <shelf>1</shelf> <card>1</card> </id>"
        else
            puts "error, no 'running' in message"
        end
    end
end

class NCPluginVer < NCPlugins
    @@instance = NCPluginVer.new
    def self.instance
        @@instance
    end

    def get_next_id
        $MESSAGE_ID_DHCP_LEASES
    end

    def set_req input
        puts "[NCPluginVer].set_req input is #{input}"
        #puts "[NCPluginVer] req is #{get_req}"
        get_req % {:object => input}
    end

    def get_req
        "<rpc message-id='#{$MESSAGE_ID_RUNNING_VER}' nodename='' timeout='35000'> <action> <action-type>show-software-card</action-type> <action-args> <object> %{object} </object> </action-args> </action> </rpc>"
    end

    #<rpc-reply length="000232" message-id="25" nodename="" timeout="35000"> <ok /> <action-reply> <present>true</present> <running>2.4.1.116</running> <committed>2.4.1.116</committed> <alternate>2.4.1.110</alternate> </action-reply> </rpc-reply>
    def parse string
        return nil unless super
        if string.size > 0 and string.include?("running")
            ver = string.match(/<running>(.*?)<\/running>/).to_a[1]
            puts "[NCPluginVer.parse] write ver to device_object"
            NCPlugins.get_device.set_ver ver
            ver
        else
            puts "error, no 'running' in message"
        end
    end
end

class NCPluginDhcpLeases < NCPlugins
    @@instance = NCPluginDhcpLeases.new
    def self.instance
        @@instance
    end

    def get_next_id
        $MESSAGE_ID_SHOW_PPPOE_SESSIONS
    end

    def get_req
        "<rpc message-id='#{$MESSAGE_ID_DHCP_LEASES}' nodename='' timeout='35000'> <action> <action-type>show-dhcp-leases</action-type> <action-args /> </action> </rpc>"
    end

    #<entry> <outer-vlan>85</outer-vlan> <inner-vlan>none</inner-vlan> <mac>00:06:31:58:27:db</mac> <port> <type>EthIntf</type> <id> <shelf>1</shelf> <card>2</card> <ethintf>110</ethintf> </id> </port> <sub-port> </sub-port> <ip>10.59.59.195</ip> <netmask>255.255.255.0</netmask> <gw>10.59.59.1</gw> <server>10.59.59.1</server> <is-static>false</is-static> <expiry-time>1435881079</expiry-time> </entry>
    def parse string
        return nil unless super
        has_dhcp_leases = "NO"
        if string.size > 0 and string.include?("<mac>")
            puts "[NCPluginDhcpLeases.parse] write DHCP Leases exist to device_object"
            has_dhcp_leases = "YES"
        else
            puts "[NCPluginDhcpLeases.parse] no DHCP Leases"
            has_dhcp_leases = "NO"
        end
        NCPlugins.get_device.set_has_dhcp_leases has_dhcp_leases
    end
end


class NCPluginShowPppoeSessions < NCPlugins
    @@instance = NCPluginShowPppoeSessions.new
    def self.instance
        @@instance
    end

    def get_next_id
        #Device type check
        mode = NCPlugins.get_device.get_mode 
        puts "Check mode [#{mode}]"
        if mode.eql? "e7-2" or mode.eql? "e7-20"
            $MESSAGE_ID_HAS_DISC_ONT
        else
            puts "[#{mode}] finish Netconf."
            nil
        end
    end

    def get_req
        "<rpc message-id='#{$MESSAGE_ID_SHOW_PPPOE_SESSIONS}' nodename='' timeout='35000'> <action> <action-type>show-pppoe-sessions</action-type> <action-args> <count>10</count> </action-args> </action> </rpc>"
    end

    def parse string
        return nil unless super
        has_pppoe_sessions = "NO"
        if string.size > 0 and string.include?("<entry>")
            puts "[NCPluginShowPppoeSessions.parse] write PPPoE Sessions exist to device_object"
            has_pppoe_sessions = "YES"
        else
            puts "[NCPluginShowPppoeSessions.parse] no PPPoE Sessions"
            has_pppoe_sessions = "NO"
        end
        NCPlugins.get_device.set_has_pppoe_sessions has_pppoe_sessions
    end
end

class NCPluginHasVDSL48C < NCPlugins
    @@instance = NCPluginHasVDSL48C.new
    def self.instance
        @@instance
    end

    def get_next_id
        nil
    end

    def get_req
		"<rpc message-id='#{$MESSAGE_ID_HAS_VDSL48C}' nodename='' timeout='35000'> <get> <filter type='subtree'> <top> <object> <type>System</type> <id /> <children> <type>Card</type> <attr-list>actual-type serno</attr-list> <attr-filter> <equip-type>vdsl2-48c</equip-type> </attr-filter> </children> </object> </top> </filter> </get> </rpc>"
    end

    def parse string
        return nil unless super
        has_vdsl48c = "NO"
        if string.size > 0 and string.include?("<serno>")
            puts "start scan SN"
            reg = /<serno>(.*?)<\/serno>/
            serno_ary = string.scan(reg) 
            pp serno_ary.flatten!
            serno_ary.each do |sn|
                puts "SN is: " + sn
                if sn != "0"
                    puts "[NCPluginHasVDSL48C.parse] write VDSL48C exist to device_object"
                    has_vdsl48c= "YES"
                    break
                end
            end
        else
            puts "[NCPluginHasVDSL48C.parse] no VDSL48C"
            has_vdsl48c = "NO"
        end
        NCPlugins.get_device.set_has_vdsl48c has_vdsl48c
    end
end

class NCPluginHasDiscOnt < NCPlugins
    @@instance = NCPluginHasDiscOnt.new
    def self.instance
        @@instance
    end

    def get_next_id
        $MESSAGE_ID_ONT_WITH_RGWAN
    end

    def get_req
		"<rpc message-id='#{$MESSAGE_ID_HAS_DISC_ONT}' nodename='' timeout='35000'> <get><filter type='subtree'><top><object><type>System</type><id/><children><type>DiscOnt</type><attr-list>pon model ont ontprof </attr-list><attr-filter/></children></object></top></filter></get> </rpc>"
    end

    def parse string
        return nil unless super
        has_disc_ont = "NO"
        if string.size > 0 and string.include?("<pon>")
            puts "[NCPluginOnt.parse] write DiscOnt exist to device_object"
            has_disc_ont = "YES"
        else
            puts "[NCPluginOnt.parse] no DiscOnt"
            has_disc_ont = "NO"
        end
        NCPlugins.get_device.set_has_disc_ont has_disc_ont
    end
end


class NCPluginOntWithRgWan < NCPlugins
    @@instance = NCPluginOntWithRgWan.new
    def self.instance
        @@instance
    end

    def get_next_id
        mode = NCPlugins.get_device.get_mode 
        puts "Check mode [#{mode}]"
        if mode.eql? "e7-2"
            $MESSAGE_ID_HAS_VDSL48C
        else
            puts "[#{mode}] finish Netconf."
            nil
        end
    end

    def get_req
		"<rpc message-id='#{$MESSAGE_ID_ONT_WITH_RGWAN}' nodename='' timeout='35000'> <get><filter type='subtree'><top><object><type>System</type><id/><children><type>OntRg</type><attr-list>rg-wan-count</attr-list><attr-filter/></children></object></top></filter></get> </rpc>"
    end

    def parse string
        return nil unless super
        ont_with_rgwan = nil
        if string.size > 0 and string.include?("<rg-wan-count>")
            #looking for the first one matching
            ont_with_rgwan = string.match(/<ont>(\d+?)<\/ont><ontslot>8<\/ontslot><ontrg>1<\/ontrg><\/id><rg-wan-count>\b[1-9]\d*\b<\/rg-wan-count>/).to_a[1]
            if ont_with_rgwan
                puts "[NCPluginVer.parse] write ont ID[#{ont_with_rgwan}] has rgwan to device_object" 
                NCPlugins.get_device.set_ont_with_rgwan ont_with_rgwan
            else
                puts "[NCPluginOnt.parse] no ONT with RgWan"
            end
        else
            puts "[NCPluginOnt.parse] no ONT with RgWan"
        end
        ont_with_rgwan
    end
end
#id = $ENTRANCE_ID
#puts "entrance id is: #{id}"
#
#plugin = NCPlugins.get_plugin id
##pretend it is as result
#result = '<rpc-reply length="000792" message-id="100" nodename="" timeout="35000"> <data> <top> <object> <type>System</type> <id> </id> <op-stat>enable</op-stat> <crit>0</crit> <maj>0</maj> <min>0</min> <warn>0</warn> <info>0</info> <derived-states>child-prov</derived-states> <create-time>1407218771</create-time> <create-time-nsec>178798000</create-time-nsec> <num-res-vlan>4</num-res-vlan> <shelf-type>e7-2slotchassis-1ru</shelf-type> <current-time>1432619939</current-time> <current-time-str>Tue May 26 13:58:59 2015</current-time-str> <uptime>96341</uptime> <active-card> <type>Card</type> <id> <shelf>1</shelf> <card>1</card> </id> </active-card> <standby-card> </standby-card> <update-time>1432601714</update-time> <master-shelf>1</master-shelf> <current-active-time>96257</current-active-time> </object> </top> </data> </rpc-reply>'
#
#puts "[main] result is: #{result}"
#
#msgid = NCPlugins.parse_msgid result
#puts "[main] msgid is: #{msgid}"
#plugin = NCPlugins.get_plugin msgid
#req = plugin.parse_send result
#puts "[main] suppose to send #{req}"
#puts ""
##pretend to send req 
#
##pretend it is as result
#result = '<rpc-reply length="000232" message-id="101" nodename="" timeout="35000"> <ok /> <action-reply> <present>true</present> <running>2.4.1.116</running> <committed>2.4.1.116</committed> <alternate>2.4.1.110</alternate> </action-reply> </rpc-reply>'
#
#puts "[main] result is: #{result}"
#msgid = NCPlugins.parse_msgid result
#puts "[main] msgid is: #{msgid}"
#plugin = NCPlugins.get_plugin msgid
#req = plugin.parse_send result
#puts "[main] suppose to send #{req}"
#puts ""


