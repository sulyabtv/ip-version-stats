from argparse import ArgumentParser
import sys
import os
from typing import Optional
import threading
import select
from datetime import datetime

import matplotlib.pyplot as plt
from matplotlib.axes import Axes

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from socket import socket, AF_PACKET, SOCK_RAW, ntohs, SOL_SOCKET, SO_BINDTODEVICE

# "Do not touch" constants
MAX_ETHERNET_FRAME_SIZE = 1518
ETH_P_IP = ntohs( 0x0800 )      # as defined in if_ether.h
ETH_P_IPV6 = ntohs( 0x86DD )    # as defined in if_ether.h

# Configurable constants
SELECT_TIMEOUT = 0.1

class Sniffer:
    def __init__( self, stop_event: threading.Event, proto: int, outpath: str, interface: Optional[ str ] = None ):
        assert proto in [ ETH_P_IP, ETH_P_IPV6 ], "Invalid address family"
        self.proto = proto
        self.af = 'IPv4' if self.proto == ETH_P_IP else 'IPv6'
        self.outpath = outpath + '.' + self.af
        self.stats = {}
        self.last_write_timestamp = datetime.now()
        try:
            print( 'Starting ' + self.af + ' sniffer..' )
            self.outfile = open( self.outpath, 'w' )
            self.sock = socket( AF_PACKET, SOCK_RAW, self.proto )
            if interface is not None:
                self.interface = interface
                self.sock.setsockopt( SOL_SOCKET, SO_BINDTODEVICE, str( self.interface + '\0' ).encode( 'utf-8' ) )
            self.stop_event = stop_event
            self.sniff_thread = threading.Thread( target=self.sniff, args=(), name=self.af )
            self.sniff_thread.start()
            print( 'Started ' + self.af + ' sniffer' )
        except Exception:
            raise

    def write_outfile( self, dump_all=False ):
        cur_timestamp = datetime.now().strftime( '%Y-%m-%d %H:%M' )
        for stat_tuple in list( self.stats ):
            ( timestamp, src, dst, transport, sport, dport ) = stat_tuple
            if dump_all or cur_timestamp[ -2: ] != timestamp[ -2: ]:  # Compare minute values
                self.outfile.write( f"{ timestamp } { src } { dst } { transport } { sport } { dport } { self.stats[ stat_tuple ] }\n" )
                del self.stats[ stat_tuple ]
        self.outfile.flush()
        self.last_write_timestamp = datetime.now()

    def sniff( self ):
        while not self.stop_event.is_set():
            sock_ready = select.select( [ self.sock ], [], [], SELECT_TIMEOUT )
            if len( sock_ready[ 0 ] ) > 0:
                raw = self.sock.recv( MAX_ETHERNET_FRAME_SIZE )
                packet = Ether( raw )
                for ip_class in [ IP, IPv6 ]:
                    if ip_class in packet:
                        ip_layer = packet.getlayer( ip_class )
                        timestamp = datetime.now()
                        src = str( ip_layer.getfieldval( 'src' ) )
                        dst = str( ip_layer.getfieldval( 'dst' ) )
                        found_transport = False
                        for transport_class in [ TCP, UDP ]:
                            if transport_class in packet:
                                found_transport = True
                                transport_layer = packet.getlayer( transport_class )
                                transport = 'TCP' if transport_class == TCP else 'UDP'
                                sport = str( transport_layer.getfieldval( 'sport' ) )
                                dport = str( transport_layer.getfieldval( 'dport' ) )
                        if not found_transport:
                            transport = 'OTH'
                            sport = dport = '0'
                        # Update stats dictionary
                        stat_tuple = ( timestamp.strftime( '%Y-%m-%d %H:%M' ), src, dst, transport, sport, dport )
                        self.stats[ stat_tuple ] = self.stats.get( stat_tuple, 0 ) + 1
                        # Write output to file if a minute or more has passed since last write
                        if ( timestamp - self.last_write_timestamp ).seconds > 60:
                            self.write_outfile()
        self.write_outfile( dump_all=True )
        self.outfile.close()
        self.sock.close()

def get_parser() -> ArgumentParser:
    parser = ArgumentParser( description="IP-Version-Stats: A tool to monitor network traffic and obtain IPv4 vs IPv6 traffic statistics. "
                                         "This tool needs to be run as root/administrator." )

    # Arguments
    parser.add_argument( '-i', '--interface', dest='interface',
                         default=None, type=str,
                         help="Name (eg: eth0) of the interface on which to monitor traffic. "
                              "If no interface name is provided, traffic will be monitored on all interfaces." )
    parser.add_argument( '-o', '--outpath', dest='outpath',
                         default='stats', type=str,
                         help="Path to the output files (OUTPATH.ipv4 and OUTPATH.ipv6 will be created). Default: <pwd>/stats" )
    parser.add_argument( '-d', '--display', action='store_true',
                         help="Display results based on packet sniff stats. Use with -o/--outpath to specify path to the output files." )

    return parser

def main():
    # Parse command line arguments
    parser = get_parser()
    args = parser.parse_args()

    if args.display:
        counts = { 'IPv4': {}, 'IPv6': {} }
        for ip_version in counts:
            with open( args.outpath +  '.' + ip_version ) as statsfile:
                for line in statsfile.readlines():
                    stat_tuple = line.split()
                    timestamp = stat_tuple[ 0 ] + ' ' + stat_tuple[ 1 ]
                    counts[ ip_version ][ timestamp ] = counts[ ip_version ].get( timestamp, 0 ) + int( stat_tuple[ -1 ] )
        # Set up plot
        fig, ( ( ax_ipv4, ax_ipv6 ) , ( ax_percentage, _ ) ) = plt.subplots( 2, 2 )
        plt.ion()
        plt.get_current_fig_manager().full_screen_toggle()
        ax_ipv4.plot( counts[ 'IPv4' ].keys(), counts[ 'IPv4' ].values() )
        ax_ipv4.set_title( 'IPv4 packet count vs Time' )
        ax_ipv4.set_xlabel( 'Timestamp' )
        ax_ipv4.set_ylabel( '# of IPv4 packets sent/received' )
        plt.draw()
        plt.waitforbuttonpress()
        sys.exit( 0 )

    # Run sniffers
    try:
        stop_event = threading.Event()
        v4sniffer = Sniffer( stop_event, ETH_P_IP, args.outpath, args.interface )
        v6sniffer = Sniffer( stop_event, ETH_P_IPV6, args.outpath, args.interface )
        print( "Startup complete. Press Ctrl+C to exit." )
        stop_event.wait()
    except OSError as e:
        sys.exit( "OSError: " + str( e ) )
    except KeyboardInterrupt:
        print( "Terminating.." )
        stop_event.set()
        v4sniffer.sniff_thread.join()
        v6sniffer.sniff_thread.join()
        sys.exit( 0 )

if __name__ == "__main__":
    # Proceed only if run as root
    if os.getuid() != 0:
        sys.exit( "Please run this tool as root/administrator." )
    main()