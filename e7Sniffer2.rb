# Description: It is a sniffer for E series. Data will be marked if default Netconf port is open.
# It is an update of e7Sniffer.rb
# 1, Input: 
# 2, Output: data will be inserted into MongoDB for Meteor
# Date: 20150609
# Author: James Wang
#==============================
$VERBOSE=nil
require "pp"
require 'rubygems'
require "Logger"
require 'net/ssh'
require 'ipaddr'
require "mongo"
require "./ncPlugin.rb"

Mongo::Logger.logger.level = Logger::WARN

$ip_found_group = <<IP_FOUND_GROUP.split("\n")
10.1
10.2
10.3
10.6
10.83
10.201
10.202
10.204
10.205
10.206
10.208
10.243
10.245
IP_FOUND_GROUP

$threads_num = 2000#50 * 255
#~ pp $0
BEGIN {p __FILE__.center(26, '=') }

$log = Logger.new(File.dirname($0) + "/log.txt")
#log.level = Logger::DEBUG
def log_puts(msg)
    puts msg
    $log.info msg
end

$ip_group = "10.245.67.*"
$default_netconf_port = 830
$default_netconf_user = %w{e7 e5 e3}
$default_netconf_passwd = 'admin'

#$data = nil
$input_array = [] #%w{a b c d e f}
$output_array = []

$sniffer_over = false
$HTML= File.dirname($0) + "/" + "EList.html"

$mongo_client = '127.0.0.1:3001'
$mongo_database = 'meteor'

class DeviceObject
  attr_accessor :ip, :schema_version, :mode, :time 
  def initialize(ip, ver, mode, time)
    @ip, @schema_version, @mode, @time = ip, ver, mode, time
  end

  def DeviceObject.decode_hello_msg(hello_msg)
      puts "Decoding hello message..."
      reg = /\[(.*)\].*http:\/\/calix.com\/(.*)\/(.*)\/config/
      decoded_ary = hello_msg.match(reg).to_a
      #pp decoded_ary
      ip = decoded_ary[1]
      ver = decoded_ary[2]
      mode = decoded_ary[3]
      time = Time.now
      rtn = DeviceObject.new(ip, mode, ver, time) if ip && mode && ver
  end

    def set_ver ver
        @ver = ver
    end

    def get_mode
        @mode
    end

    def set_has_dhcp_leases has_dhcp_leases
        @has_dhcp_leases = has_dhcp_leases
    end

    def set_has_pppoe_sessions has_pppoe_sessions
        @has_pppoe_sessions = has_pppoe_sessions
    end

    def set_has_vdsl48c has_vdsl48c
        @has_vdsl48c = has_vdsl48c
    end

    def set_has_disc_ont has_disc_ont
        @has_disc_ont = has_disc_ont
    end

    def set_ont_with_rgwan ont_with_rgwan
        @ont_with_rgwan= ont_with_rgwan
    end

  def to_s
      "IP: [#{@ip}], Mode: [#{@mode}], Schema Version: [#{@schema_version}], Time: [#{@time}]"
  end

    def to_mongo
        puts "Client: #{$mongo_client}, Database Name: #{$mongo_database}"
        client = Mongo::Client.new([ $mongo_client ], :database => $mongo_database)
        #INSERT or Update
        #Collection name is devices
        count = client[:devices].find(:ip => @ip).count
        puts "count of #{ip} is #{count}"
        if 0 == count
            result = client[:devices].insert_one( { :ip => @ip, :schema_version => @schema_version, :mode => @mode, :create_time => @time, :ver => @ver, :has_dhcp_leases => @has_dhcp_leases, :has_pppoe_sessions => @has_pppoe_sessions, :has_vdsl48c => @has_vdsl48c, :has_disc_ont => @has_disc_ont, :ont_with_rgwan => @ont_with_rgwan} )
            log_puts "[#{result.n} result is inserted for ip[#{@ip}]"
        else
            result = client[:devices].find(:ip => @ip).update_many("$set" => { :schema_version => @schema_version, :mode => @mode, :create_time => @time, :ver => @ver, :has_dhcp_leases => @has_dhcp_leases, :has_pppoe_sessions => @has_pppoe_sessions, :has_vdsl48c => @has_vdsl48c, :has_disc_ont => @has_disc_ont, :ont_with_rgwan => @ont_with_rgwan} )
            log_puts "[#{result.n} result is updated for ip[#{@ip}]"
        end
    end

end

#================================================================

class IPFound
    @@COMMENT_IP_NOW = "#IP Now"
    @@COMMENT_IP_FOUND = "#IP Found"
    @@IP_FOUND_FILE = File.dirname($0) + "/" + "IPFound"
    #ip_now is like 10.45.1
    @@ip_now = nil

    attr_accessor :ip_found_ary
    def initialize()
        @ip_found_ary = []
        #if file exit, load it 
        load_file if File.exist? @@IP_FOUND_FILE
    end

    def self.get_ip_now
        @@ip_now
    end

    def get_ip_found_ary
        @ip_found_ary
    end

    def self.clear_file
        open(@@IP_FOUND_FILE, 'w') do |f|
            f.puts ""
        end
    end

    def load_file
        #puts "load_file"
        get_ip_now = false
        get_ip_found = false
        open(@@IP_FOUND_FILE).each do |line|
            #puts line
            if line.include? @@COMMENT_IP_NOW
                get_ip_now = true
                next 
            end

            if get_ip_now
                @@ip_now = line.chop
                get_ip_now = false
                next
            end

            if line.include? @@COMMENT_IP_FOUND
                get_ip_found = true 
                next
            end

            if get_ip_found 
                #puts "line is: " + line
                @ip_found_ary << line.chop
                next
            end
        end
        #puts "Load file with: "
        #puts to_s
    end

    def to_s
        rtn = @@COMMENT_IP_NOW + "\n"
        rtn += @@ip_now + "\n"
        rtn += @@COMMENT_IP_FOUND + "\n"
        @ip_found_ary.each do |ip|
            rtn += ip + "\n"
        end
        rtn
    end

    def write_file(ip_now, ip_found_ary)
        log_puts "Log result for [#{ip_now}] ..."
        #Update IP now
        @@ip_now = ip_now
        #Attach new found
        @ip_found_ary += ip_found_ary
        #puts to_s
        open(@@IP_FOUND_FILE, 'w') do |f|
            f.puts to_s
        end
        log_puts "End write file."
    end
end
#================================================================

class SnifferAction
    attr_accessor :ip
    @@sniffer_ip_found_ary = []
    def initialize(ip)
        @ip = ip
    end

    def self.get_ip_found_ary
        @@sniffer_ip_found_ary
    end

    def self.set_ip_found_ary(ary)
        @@sniffer_ip_found_ary = ary
    end

    # SSH channel and subsystem is used for input
    def sniff(ip, port, user, passwd)
        puts "sniffing #{ip} port #{port} as #{user} with password #{passwd}..."

        #Add SSH fingerprint mismatch exception handling.
        begin
            Net::SSH.start(ip, user, :port=>port, :password=>passwd, :timeout=>6, :non_interactive=>true) do |session|

                session.open_channel do |channel|

                    channel[:data] = ""
                    @flag_close_channel = false

                    device_object = nil

                    channel.request_pty do |ch, success|
                        raise "Error requsting pty" unless success

                        # Use this method unless it is a CLI
                        #ch.send_channel_request("shell") do |ch, success|
                            #raise "Error opening shell" unless success
                        #end
                        
                        # need Netconf subsystem
                        channel.subsystem("netconf") do |ch, success|
                            raise "Error requesting netconf subsystem." unless success
                        end
                    end

                    channel.on_data do |ch, data|
                        #STDOUT.print data
                        channel[:data] << data
                    end

                    channel.on_process do |ch|
                        if @flag_close_channel == false and channel[:data].size > 0 and channel[:data].include?("hello")
                            log_puts "Found [#{ip}] has Netconf response."
                            #@@sniffer_ip_found_ary << ip
                            hellomsg = channel[:data]
                            #$input_array << "[" +  ip + "]" + hellomsg
                            log_puts "[#{ip}] has Netconf response [#{hellomsg}]"

                            #decode hello message and create DeviceObject
                            device_object = DeviceObject.decode_hello_msg("[" +  ip + "]" + hellomsg)
                            #initial device for plugin
                            NCPlugins.set_device device_object

                            #check mode
                            mode = device_object.get_mode 
                            req = nil
                            if mode.eql? "e5-400" or mode.eql? "e5-312"
                                req = NCPlugins.get_close_str
                                puts "It is [#{mode}]. And to send request: #{req}"
                            else
                                #entrance id setting
                                msgid = $ENTRANCE_ID
                                puts "entrance id is: #{msgid}"
                                plugin = NCPlugins.get_plugin msgid
                                req = plugin.get_req
                                puts "[main] suppose to send #{req}"
                            end

                            channel[:data] = ""
                            ch.send_data req 
                        elsif channel[:data].size > 0 and !channel[:data].include?("</rpc-reply>")
                            puts "Netconf message is not end yet, keep waiting ..."
                        elsif @flag_close_channel == false and channel[:data].size > 0 
                            puts "in Channel..."

                            result = channel[:data]
                            log_puts "[#{ip}] has Netconf response [#{result}]"

                            msgid = NCPlugins.parse_msgid result
                            puts "[main] msgid is: #{msgid}"

                            if msgid != $MESSAGE_ID_END
                                plugin = NCPlugins.get_plugin msgid
                                req = plugin.parse_send result
                                puts "[main] suppose to send #{req}"

                                channel[:data] = ""
                                ch.send_data req 
                            else
                                puts "[main] end Netconf, start writing device object to database"
                                device_object.to_mongo 
                                @flag_close_channel = true
                            end

                            puts "out Channel..."
                            puts ""
                        end
                    end

                    channel.on_extended_data do |ch, type, data|
                        STDOUT.print "Error: #{data}\n"
                    end

                    channel.on_request("exit-status") do |ch,data|
                        puts "in on_request exit-status"
                        exit_code = data.read_long
                    end
                    
                    channel.on_request("exit-signal") do |ch, data|
                        puts "in on_request exit-signal"
                        exit_signal = data.read_long
                    end

                    channel.on_eof do |ch|
                        puts "remote end is done sending data"
                    end

                    channel.on_close do |ch|
                      puts "channel is closing!"
                    end

                    session.loop
                end #Session end
            end #Net end
        rescue Net::SSH::HostKeyMismatch => e
        # The rescue block is used to ignore the change in key and still login using ssh
          log_puts "[HostKeyMismatch for #{ip}] remembering new key: #{e.fingerprint}"
          e.remember_host!
          retry
        end
    end
    
    def SnifferAction.build_html
        ip_ary = IPFound.new().get_ip_found_ary
        puts "IP found is empty."; return nil if ip_ary == nil or ip_ary.size ==0

        pp ip_ary
        pp "There are [#{ip_ary.length}] devices to be sniffered."
        ip_ary.each do |x|
            #Added into $input_array for msg
            SnifferAction.new(x).action()
        end
    end

    def action()
        $default_netconf_user.each do |usr|
            begin
                sniff(@ip, $default_netconf_port, usr, $default_netconf_passwd)
                break;
            rescue Net::SSH::AuthenticationFailed
                puts "AuthenticationFailed"
            rescue Errno::ECONNREFUSED
                puts "Netconf Rejected"
                break
            rescue Errno::ETIMEDOUT
                puts "Connecting Timeout"
                break
            rescue StandardError => err
                puts err
                break
            end
        end
    end
end
#===================================================================================================
puts "*" * 36
#cli_msg = "Which operation you gonna do? Please input number.\n"
#cli_msg << "1 - Sniff E7 with Found IP.\n"
#choose = nil
#loop do
#    if choose
#        choose.chop!
#        puts "choose: " + choose
#    end
#
#    if  !(/[123]/ =~ choose)
#        puts cli_msg
#        choose = gets
#    else
#        break
#    end
#end
#
#if choose == "1"
    SnifferAction.build_html
#end

