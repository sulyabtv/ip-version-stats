from argparse import ArgumentParser
from operator import itemgetter
import sys
import os
from typing import Optional
import threading
import select
from datetime import datetime

import matplotlib.pyplot as plt
from matplotlib.axes import Axes
from matplotlib.ticker import MaxNLocator
import numpy

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from socket import socket, gethostbyaddr, AF_PACKET, SOCK_RAW, ntohs, SOL_SOCKET, SO_BINDTODEVICE
from ipaddress import ip_address

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

def _resolve( addr: str ):
    try:
        if ip_address( addr ).is_private:
            return None
        result = gethostbyaddr( addr )
        result_split = result[ 0 ].split( '.' )
        if len( result_split ) > 1:
            return result_split[ -2 ] + '.' + result_split[ -1 ]    # 123.foo-bar.xyz.com -> xyz.com
        else:
            return result_split[ 0 ]
    except OSError:
        return None

def resolve_domain( from_addr: str, to_addr: str, resolved: dict[ str, Optional[ str ] ], unresolved: list[ str ] ):
    if resolved.get( from_addr, None ):
        return resolved[ from_addr ]
    elif resolved.get( to_addr, None ):
        return resolved[ to_addr ]
    else:
        for addr in ( from_addr, to_addr ):
            if addr not in unresolved:
                result = _resolve( addr )
                if result:
                    resolved[ addr ] = result
                    return result
                else:
                    unresolved.append( addr )
        return None

def main():
    # Parse command line arguments
    parser = get_parser()
    args = parser.parse_args()

    if args.display:
        counts = { 'IPv4': {}, 'IPv6': {} }
        resolved = {}
        unresolved = []
        domain_counts: dict[ str, dict ] = {}
        for ip_version in counts:
            with open( args.outpath +  '.' + ip_version ) as statsfile:
                for line in statsfile.readlines():
                    stat_tuple = line.split()
                    timestamp = stat_tuple[ 0 ] + ' ' + stat_tuple[ 1 ]
                    counts[ ip_version ][ timestamp ] = counts[ ip_version ].get( timestamp, 0 ) + int( stat_tuple[ -1 ] )
                    domain = resolve_domain( stat_tuple[ 2 ], stat_tuple[ 3 ], resolved, unresolved )
                    if domain:
                        if domain not in domain_counts:
                            domain_counts[ domain ] = { 'IPv4': 0, 'IPv6': 0 }
                        domain_counts[ domain ][ ip_version ] += int( stat_tuple[ -1 ] )

        # Set up plot
        fig, ( ax_count, ax_domainwise ) = plt.subplots( 2, 1 )
        plt.ion()
        plt.get_current_fig_manager().full_screen_toggle()
        # Plot 1: IPv4 and IPv6 packet counts vs Time
        for ip_version, color in zip( counts.keys(), ( 'blue', 'green' )):
            ax_count.plot( counts[ ip_version ].keys(), counts[ ip_version ].values(), color=color, label=ip_version )
        ax_count.set_title( 'IPv4 and IPv6 packet counts vs Time' )
        ax_count.set_xlabel( 'Timestamp' )
        ax_count.set_ylabel( '# of packets sent/received' )
        ax_count.xaxis.set_major_locator( MaxNLocator( 5 ) )
        ax_count.legend( loc='upper right' )
        # Plot 2: IPv4 vs IPv6 stats for domains with the highest traffic
        domain_totals = sorted( { domain: sum( counts.values() ) for domain, counts in domain_counts.items() }.items(),
                                key=itemgetter( 1 ),
                                reverse=True )[ :10 ]
        x_values = [ entry[ 0 ] for entry in domain_totals ]
        y_values_ipv4 = [ domain_counts[ entry[ 0 ] ][ 'IPv4' ] for entry in domain_totals ]
        y_values_ipv6 = [ domain_counts[ entry[ 0 ] ][ 'IPv6' ] for entry in domain_totals ]
        x_points = numpy.arange( len( x_values ) )
        ax_domainwise.bar( x_points - 0.2, y_values_ipv4, width=0.2, color='b', align='edge', label='IPv4' )
        ax_domainwise.bar( x_points, y_values_ipv6, width=0.2, color='g', align='edge', label='IPv6' )
        ax_domainwise.set_xticks( x_points, x_values )
        ax_domainwise.set_title( 'IPv4 vs IPv6 stats for domains with the highest traffic' )
        ax_domainwise.set_xlabel( 'Domain' )
        ax_domainwise.set_ylabel( '# of packets sent/received' )
        ax_domainwise.legend( loc='upper right' )
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
    # if os.getuid() != 0:
    #     sys.exit( "Please run this tool as root/administrator." )
    main()