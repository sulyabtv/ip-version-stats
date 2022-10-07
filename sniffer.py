from argparse import ArgumentParser
import sys
import os
from typing import Optional
import threading
from datetime import datetime
import signal

from scapy.all import get_if_list, conf
from scapy.sendrecv import AsyncSniffer
from scapy.sessions import IPSession
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

class Sniffer:
    def __init__( self, outpath: str, interface: Optional[ str ] ):
        self.outpath = outpath
        self.interface = interface
        self.stats = {}
        self.last_write_timestamp = datetime.now()
        try:
            print( "Starting sniffer" + ( "" if not self.interface else " on interface " + self.interface ) + ".." )
            self.outfile = open( self.outpath, 'w' )
            self.sniffer = AsyncSniffer( iface=self.interface,
                                         session=IPSession,
                                         store=False,
                                         prn=lambda packet: self.process_packet( packet ) )
            self.sniffer.start()
            print( "Started sniffer" + ( "" if not self.interface else " on interface " + self.interface ) )
        except Exception:
            raise

    def stop( self ):
        self.sniffer.stop( join=True )
        self.write_outfile( dump_all=True )
        self.outfile.close()

    def write_outfile( self, dump_all=False ):
        cur_timestamp = datetime.now().strftime( '%Y-%m-%d %H:%M' )
        for stat_tuple in list( self.stats ):
            ( timestamp, version, src, dst, transport, sport, dport ) = stat_tuple
            if dump_all or cur_timestamp[ -2: ] != timestamp[ -2: ]:  # Compare minute values
                self.outfile.write( f"{ timestamp } { version } { src } { dst } { transport } { sport } { dport } { self.stats[ stat_tuple ] }\n" )
                del self.stats[ stat_tuple ]
        self.outfile.flush()
        self.last_write_timestamp = datetime.now()

    def process_packet( self, packet: Packet ):
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
                stat_tuple = ( timestamp.strftime( '%Y-%m-%d %H:%M' ), "4" if ip_class == IP else "6", src, dst, transport, sport, dport )
                self.stats[ stat_tuple ] = self.stats.get( stat_tuple, 0 ) + 1
                # Write output to file if a minute or more has passed since last write
                if ( timestamp - self.last_write_timestamp ).seconds > 60:
                    self.write_outfile()

def get_parser() -> ArgumentParser:
    parser = ArgumentParser( description="IP-Version-Stats: A tool to monitor network traffic and obtain IPv4 vs IPv6 traffic statistics. "
                                         "This sniffer tool needs to be run as root/administrator." )

    # Arguments
    parser.add_argument( '-i', '--interface', dest='interface',
                         default=None, type=str,
                         help="Name (eg: eth0) of the interface on which to monitor traffic. "
                              "If no interface name is provided, traffic will be monitored on all interfaces." )
    parser.add_argument( '-d', '--duration', dest='duration',
                         default=None, type=int,
                         help="Duration (in seconds) to run the sniffer. "
                              "If not provided, the sniffer will be run until the user issues Ctrl+C (KeyboardInterrupt)" )
    parser.add_argument( '-o', '--outpath', dest='outpath',
                         default='stats.txt', type=str,
                         help="Path to the output file (OUTPATH will be created or overwritten). Default: <pwd>/stats.txt" )

    return parser

def _raiseKeyboardInterrupt( *args ):  # Hack to make Ctrl+C work in Windows
    raise KeyboardInterrupt

def main():
    # Parse command line arguments
    parser = get_parser()
    args = parser.parse_args()

    # Proceed on Linux only if run as root
    if os.name == 'posix':
        if os.getuid() != 0:
            sys.exit( "Please run this tool as root/administrator." )
    # If running on Windows, do not run in promiscuous mode
    elif os.name == 'nt':
        conf.sniff_promisc = False
    # java is untested for now
    else:
        sys.exit( "Unsupported platform" )

    # Sanity checks
    if args.duration is not None and args.duration <= 0:
        sys.exit( "Error: Duration must be an integer greater than 0" )
    if args.interface is not None and args.interface not in get_if_list():
        sys.exit( "Error: Unknown interface name" )

    # Run sniffer
    try:
        stop_event = threading.Event()
        sniffer = Sniffer( args.outpath, interface=args.interface )
        if args.duration is not None:
            print( "Sniffer will exit automatically in " + str( args.duration ) + " seconds." )
        else:
            print( "Press Ctrl+C (or equivalent) to stop the sniffer." )
        signal.signal( signal.SIGINT, _raiseKeyboardInterrupt )
        stop_event.wait( timeout=args.duration )
    except OSError as e:
        sys.exit( "OSError: " + str( e ) )
    except KeyboardInterrupt:
        print( "Terminating.." )

    # Stop sniffer and flush any remaining output
    sniffer.stop()

if __name__ == "__main__":
    main()