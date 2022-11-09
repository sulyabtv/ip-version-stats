from argparse import ArgumentParser
import subprocess
import sys
import os
import time
from typing import Optional
from datetime import datetime
import re
import threading

from scapy.all import get_if_list

NUM_LINES_PER_CHUNK = 5000

class Sniffer:
    def __init__( self, outpath: str, interface: Optional[ str ] ):
        self.outpath = outpath
        self.interface = interface
        self.stats = {}
        self.last_write_timestamp = datetime.now()
        self.tcpdump_process = None
        self.sniffer_stop_event = threading.Event()
        self.parser_stop_event = threading.Event()
        self.pattern = re.compile( "(.*):\d\d\.\d+ (IP|IP6) (.*)\.(\d+) > (.*)\.(\d+): (UDP|tcp).* (\d+)" )
        self.lines = []
        try:
            print( "Starting sniffer" + ( "" if not self.interface else " on interface " + self.interface ) + ".." )
            self.outfile = open( self.outpath, 'a' )
            self.launch_tcpdump()
            self.sniffer_thread = threading.Thread( target=self.sniff, args=(), name='sniffer_thread' )
            self.parser_thread = threading.Thread( target=self.parse, args=(), name='parser_thread' )
            self.sniffer_thread.start()
            self.parser_thread.start()
            print( "Started sniffer" + ( "" if not self.interface else " on interface " + self.interface ) )
        except Exception:
            raise

    def write_outfile( self, dump_all=False ):
        cur_timestamp = datetime.now().strftime( '%Y-%m-%d %H:%M' )
        for stat_tuple in list( self.stats ):
            ( timestamp, version, src_ip, src_port, dst_ip, dst_port, transport ) = stat_tuple
            if dump_all or cur_timestamp[ -1 ] != timestamp[ -1 ]:  # Compare minute values
                self.outfile.write( f"{ timestamp } { version } { src_ip } { src_port } { dst_ip } { dst_port } { transport } "
                                    f"{ self.stats[ stat_tuple ][ 'count' ] } { self.stats[ stat_tuple ][ 'len' ] }\n" )
                del self.stats[ stat_tuple ]
        self.outfile.flush()
        self.last_write_timestamp = datetime.now()

    def process_line( self, line: str ):
        ( timestamp, version, src_ip, src_port, dst_ip, dst_port, transport, length ) = self.pattern.match( line ).groups()
        # Update stats dictionary
        stat_tuple = ( timestamp, version, src_ip, src_port, dst_ip, dst_port, transport )
        if stat_tuple not in self.stats:
            self.stats[ stat_tuple ] = { 'count': 0, 'len': 0 }
        self.stats[ stat_tuple ][ 'count' ] += 1
        self.stats[ stat_tuple ][ 'len' ] += int( length )
        return timestamp

    def parse( self ):
        while not self.parser_stop_event.is_set():
            chunk = self.lines[ :NUM_LINES_PER_CHUNK ]
            self.lines = self.lines[ NUM_LINES_PER_CHUNK: ]
            print( len( self.lines ) )
            timestamp = None
            for line in chunk:
                timestamp = self.process_line( line )
            if timestamp is not None and ( ( datetime.strptime( timestamp, '%Y-%m-%d %H:%M' ) - self.last_write_timestamp ).seconds > 60 ):
                self.write_outfile()
            time.sleep( 0.5 )   # Do not overwhelm the system when load is high
        # tcpdump has exited. Process any remaining lines
        for line in self.lines:
            self.process_line( line )
        self.write_outfile( dump_all=True )
        self.outfile.close()

    def sniff( self ):
        while not self.sniffer_stop_event.is_set():
            line = self.tcpdump_process.stdout.readline().decode( 'utf-8' )
            if 'IP' in line:    # '' or '\n' or similar junk
                self.lines.append( line ) # use another thread for consuming x number of lines every y seconds from self.lines and processing them
        # tcpdump has exited. Consume any remaining output
        for line in self.tcpdump_process.stdout.readlines():
            line = line.decode( 'utf-8' )
            if 'IP' in line:
                self.lines.append( line )
        # Print tcpdump stats
        print( 'tcpdump stats:' )
        for line in self.tcpdump_process.stderr.readlines()[ -3: ]:
            print( line.decode( 'utf-8' )[ :-1 ] )

    def launch_tcpdump( self ):
        try:
            self.tcpdump_process = subprocess.Popen( [ 'tcpdump', '-i', self.interface, '-n', '-B', '4096', '-q', '-tttt', 'udp or tcp' ],
                                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE )
        except Exception as e:
            print( "Unexpected Error: ", str( e ) )

    def stop( self ):
        self.tcpdump_process.terminate()
        self.sniffer_stop_event.set()
        self.sniffer_thread.join()
        self.parser_stop_event.set()
        self.parser_thread.join()

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
        pass
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
        sniffer = Sniffer( args.outpath, interface=args.interface )
        if args.duration is not None:
            print( "Sniffer will exit automatically in " + str( args.duration ) + " seconds. Press Ctrl+C (or equivalent) to stop early." )
            time.sleep( args.duration )
        else:
            print( "Press Ctrl+C (or equivalent) to stop the sniffer." )
            while True:
                time.sleep( 0.5 )
    except OSError as e:
        sys.exit( "OSError: " + str( e ) )
    except KeyboardInterrupt:
        print( "Terminating.." )

    # Stop sniffer and flush any remaining output
    sniffer.stop()

if __name__ == "__main__":
    main()