from argparse import ArgumentParser
import subprocess
import sys
import os
import shlex

from scapy.all import get_if_list

COUNTERS_CONF_FILE = 'counters.nft'

def get_parser() -> ArgumentParser:
    parser = ArgumentParser( description="IP-Version-Stats: A tool to monitor network traffic and obtain IPv4 vs IPv6 traffic statistics. "
                                         "This sniffer tool needs to be run as root." )

    # Arguments
    parser.add_argument( '-i', '--interface', dest='interface',
                         default='br-lan', type=str,
                         help="Name of the interface on which to monitor traffic. Default: br-lan" )
    parser.add_argument( '-o', '--outpath', dest='outpath',
                         default='/tmp', type=str,
                         help="Path to which output files will be written WITHOUT trailing forward slash. Default: /tmp" )

    return parser

def configure_nft_counters( interface: str ):
    # Hacky af but will do for now
    with open( COUNTERS_CONF_FILE, 'r' ) as f:
        counters_file_contents = f.read()
    counters_file_contents = counters_file_contents.replace( '"br-lan"', '"' + interface + '"' )
    with open( COUNTERS_CONF_FILE, 'w' ) as f:
        f.write( counters_file_contents )
    # Configure nftables counters
    subprocess.run( [ 'nft', '-f', COUNTERS_CONF_FILE ] )
    # Revert the conf file
    counters_file_contents = counters_file_contents.replace( '"' + interface + '"', '"br-lan"' )
    with open( COUNTERS_CONF_FILE, 'w' ) as f:
        f.write( counters_file_contents )

def launch_tcpdump( interface: str, outpath: str ):
    try:
        # Good luck
        cap_str_sample = ( "((tcp && ((((tcp[16] & 0x03) == 0x03) && (tcp[17] == 0xAA)) || "    # Match roughly 1/1024 of IPv4 TCP packets
                           "          (((ip6[56] & 0x03) == 0x03) && (ip6[57] == 0xAA)))) || "  # Match roughly 1/1024 of IPv6 TCP packets
                           " (udp && ((((ip[10] & 0x03) == 0x03) && (ip[11] == 0xAA)) ||"       # Match roughly 1/1024 of IPv4 UDP packets
                           "          (((ip6[46] & 0x03) == 0x03) && (ip6[47] == 0xAA)))))" )   # Match roughly 1/1024 of IPv6 UDP packets
        cap_path = outpath + '/ipvs%H%M%S.cap'
        tcpdump_cmd = f'tcpdump -i {interface} -B 4096 -s100 -w {cap_path} -G 300 "{cap_str_sample}"'
        tcpdump_process = subprocess.Popen( shlex.split( tcpdump_cmd ), stderr=subprocess.DEVNULL )
        print( f'Launched tcpdump process with pid {tcpdump_process.pid}' )
    except Exception as e:
        sys.exit( "Error while launching tcpdump: " + str( e ) )

def configure_cron( interface: str, outpath: str ):
    try:
        cwd = os.getcwd()
        cron_cmd = ( f'(crontab -l >/dev/null; echo "*/5 * * * * {cwd}/sniffer.py -c -i {interface} -o {outpath} &> /tmp/sniffer.log &") |'
                    ' sort - | uniq - | crontab -' )
        subprocess.run( cron_cmd, shell=True, check=True )
        subprocess.run( '/etc/init.d/cron restart', shell=True, check=True )
    except:
        sys.exit( "Error: Could not configure cron job" )

def main():
    # Proceed only if run as root
    if os.name == 'posix':
        if os.getuid() != 0:
            sys.exit( "Please run this tool as root." )

    # Parse command line arguments
    parser = get_parser()
    args = parser.parse_args()

    # Sanity checks
    if args.interface not in get_if_list():
        sys.exit( "Error: Unknown interface name" )

    # Configure counters if not already configured
    counters = subprocess.run( [ 'nft', 'list', 'counters', 'ip', 'v4PktCounters' ], stderr=subprocess.PIPE )
    if counters.stderr:
        print( 'Configuring nftables counters..' )
        configure_nft_counters( args.interface )
    print( 'Launching tcpdump..' )
    launch_tcpdump( args.interface, args.outpath )
    print( 'Configuring cron job..' )
    configure_cron( args.interface, args.outpath )

    print( "Configuration complete." )

if __name__ == "__main__":
    main()