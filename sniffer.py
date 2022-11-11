from argparse import ArgumentParser
import subprocess
import sys
import os
import time
from datetime import datetime
import re
import threading

from scapy.all import get_if_list

NUM_LINES_PER_CHUNK = 500
WRITE_INTERVAL = 300
COUNTERS_CONF_FILE = 'counters.nft'

class Sniffer:
    def __init__( self, outpath: str, counters: bool, interface: str ):
        self.outpath = outpath
        self.counters = counters
        self.interface = interface
        self.filename = datetime.strftime( datetime.now(), '%Y-%m-%d_%H%M' )
        self.stats = {}
        self.last_write_timestamp = datetime.now()
        self.tcpdump_process = None
        self.sniffer_stop_event = threading.Event()
        self.parser_stop_event = threading.Event()
        self.pattern = re.compile( "(.*):\d\d\.\d+ (IP|IP6) (.*)\.(\d+) > (.*)\.(\d+): (UDP|tcp).*" )
        self.lines = []
        try:
            print( "Starting sniffer" + ( "" if not self.interface else " on interface " + self.interface ) + ".." )
            self.full_path_base = self.outpath + '/' + self.filename
            self.outfile_cap = open( self.full_path_base + '.cap', 'w' )
            if self.counters:
                self.outfile_cnt = open( self.full_path_base + '.cnt', 'w' )
                self.configure_nft_counters()
                print( f"Output files: { self.full_path_base }.cap, { self.full_path_base }.cnt" )
            else:
                print( f"Output file: { self.full_path_base }.cap" )
            self.launch_tcpdump()
            self.sniffer_thread = threading.Thread( target=self.sniff, args=(), name='sniffer_thread' )
            self.parser_thread = threading.Thread( target=self.parse, args=(), name='parser_thread' )
            self.sniffer_thread.start()
            self.parser_thread.start()
            print( "Started sniffer" + ( "" if not self.interface else " on interface " + self.interface ) )
        except Exception:
            raise

    def write_outfiles( self, dump_all=False ):
        cur_timestamp = datetime.now().strftime( '%Y-%m-%d %H:%M' )
        for stat_tuple in list( self.stats ):
            ( timestamp, version, src_ip, src_port, dst_ip, dst_port, transport ) = stat_tuple
            if dump_all or cur_timestamp[ -1 ] != timestamp[ -1 ]:  # Compare minute values
                self.outfile_cap.write( f"{ timestamp } { version } { src_ip } { src_port } { dst_ip } { dst_port } { transport } "
                                        f"{ self.stats[ stat_tuple ] }\n" )
                del self.stats[ stat_tuple ]
        self.outfile_cap.flush()
        if self.counters:
            counters_output = subprocess.run( [ 'nft', 'list', 'counters' ], stdout=subprocess.PIPE )
            self.outfile_cnt.write( "Counters at " + cur_timestamp + ":\n" )
            self.outfile_cnt.write( counters_output.stdout.decode( 'utf-8' ) + '\n' )
            self.outfile_cnt.flush()
        self.last_write_timestamp = datetime.now()

    def process_line( self, line: str ):
        matched = self.pattern.match( line )
        if matched is not None:
            ( timestamp, version, src_ip, src_port, dst_ip, dst_port, transport ) = matched.groups()
            # Update stats dictionary
            stat_tuple = ( timestamp, version, src_ip, src_port, dst_ip, dst_port, transport )
            self.stats[ stat_tuple ] = self.stats.get( stat_tuple, 0 ) + 1
        else:
            print( "Could not parse tcpdump output: " + line )

    def parse( self ):
        while not self.parser_stop_event.is_set():
            chunk = self.lines[ :NUM_LINES_PER_CHUNK ]
            self.lines = self.lines[ NUM_LINES_PER_CHUNK: ]
            for line in chunk:
                self.process_line( line )
            if ( datetime.now() - self.last_write_timestamp ).seconds > WRITE_INTERVAL:
                self.write_outfiles()
            time.sleep( 1 )   # Do not overwhelm the system when load is high
        # tcpdump has exited. Process any remaining lines
        for line in self.lines:
            self.process_line( line )
        self.write_outfiles( dump_all=True )
        self.outfile_cap.close()
        if self.counters:
            self.outfile_cnt.close()

    def sniff( self ):
        while not self.sniffer_stop_event.is_set():
            line = self.tcpdump_process.stdout.readline().decode( 'utf-8' )
            if 'IP' in line:    # '' or '\n' or similar junk
                self.lines.append( line ) # use another thread for processing the captured output
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
            # God died the day this unholy piece of code was written
            capture_str = ( "(((tcp[13] & 0x12) == 0x12) ||"                    # Match IPv4 TCP SYN+ACK packets
                            " (ip6[6] == 6 && ((ip6[53] & 0x12) == 0x12)) ||"   # Match IPv6 TCP SYN+ACK packets
                            " (udp && (((ip[11] & 0x7F) == 0x7F) ||"            # Match roughly 1/128 of IPv4 UDP packets
                            "          ((ip6[47] & 0x7F) == 0x7F))))" )         # Match roughly 1/128 of IPv6 UDP packets
            self.tcpdump_process = subprocess.Popen( [ 'tcpdump', '-i', self.interface, '-n', '-B', '4096', '-q', '-tttt', '-s100', capture_str ],
                                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE )
        except Exception as e:
            print( "Unexpected Error: ", str( e ) )

    def configure_nft_counters( self ):
        # Hacky af but will do for now
        with open( COUNTERS_CONF_FILE, 'r' ) as f:
            counters_file_contents = f.read()
        counters_file_contents = counters_file_contents.replace( '"br-lan"', '"' + self.interface + '"' )
        with open( COUNTERS_CONF_FILE, 'w' ) as f:
            f.write( counters_file_contents )
        # Delete relevant tables if they already exist
        subprocess.run( [ 'nft', 'delete', 'table', 'ip', 'IPv4Stats' ] )
        subprocess.run( [ 'nft', 'delete', 'table', 'ip6', 'IPv6Stats' ] )
        # Configure nftables counters
        subprocess.run( [ 'nft', '-f', COUNTERS_CONF_FILE ] )
        # Revert the conf file
        counters_file_contents = counters_file_contents.replace( '"' + self.interface + '"', '"br-lan"' )
        with open( COUNTERS_CONF_FILE, 'w' ) as f:
            f.write( counters_file_contents )

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
                         default='br-lan', type=str,
                         help="Name (eg: eth0) of the interface on which to monitor traffic. Default: br-lan" )
    parser.add_argument( '-d', '--duration', dest='duration',
                         default=None, type=int,
                         help="Duration (in seconds) to run the sniffer. "
                              "If not provided, the sniffer will be run until the user issues Ctrl+C (KeyboardInterrupt)" )
    parser.add_argument( '-o', '--outpath', dest='outpath',
                         default='.', type=str,
                         help="Path (eg: /tmp) to which output files will be written WITHOUT trailing forward slash. Default: ." )
    parser.add_argument( '-c', '--counters', dest='counters', action='store_const',
                         const=True, default=False,
                         help="Configure nftables counters for IPv4/v6 statistics" )

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
    if args.interface not in get_if_list():
        sys.exit( "Error: Unknown interface name" )

    # Run sniffer
    try:
        sniffer = Sniffer( args.outpath, args.counters, args.interface )
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