from argparse import ArgumentParser
from operator import itemgetter
import sys
from typing import Optional
from datetime import datetime

import matplotlib.pyplot as plt
from matplotlib import dates
import numpy
from tqdm import tqdm

from socket import gethostbyaddr, gethostname, getaddrinfo
from ipaddress import ip_address

def get_parser() -> ArgumentParser:
    parser = ArgumentParser( description="IP-Version-Stats: A tool to monitor network traffic and obtain IPv4 vs IPv6 traffic statistics." )

    # Arguments
    parser.add_argument( '-o', '--outpath', dest='outpath',
                         default='stats.txt', type=str,
                         help="Path to the output file created by the sniffer tool. Default: <pwd>/stats.txt" )
    parser.add_argument( '-rt', '--require-transport', dest='require_transport',
                         default=False, action='store_true',
                         help="Only consider TCP/UDP flows" )

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

def resolve_domain( from_addr: str, to_addr: str, resolved: dict[ str, Optional[ str ] ], unresolved: list[ str ], ignored: list[ str ] ):
    if from_addr in resolved:
        return resolved[ from_addr ]
    elif to_addr in resolved:
        return resolved[ to_addr ]
    else:
        for addr in ( from_addr, to_addr ):
            if addr not in ignored and addr not in unresolved:
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

    counts = { 'IPv4': {}, 'IPv6': {} }
    resolved = {}   # Cache of resolved IPs
    unresolved = [] # Tried resolving but failed
    ignored = [ entry[ -1 ][ 0 ] for entry in getaddrinfo( gethostname(), 0 ) ] # Do not resolve our own IP address
    domain_counts: dict[ str, dict ] = {}
    with open( args.outpath ) as statsfile:
        for line in tqdm( statsfile.readlines() ):
            stat_tuple = line.split()
            if args.require_transport and stat_tuple[ 5 ] == 'OTH':
                continue
            timestamp = datetime.strptime( stat_tuple[ 0 ] + ' ' + stat_tuple[ 1 ], '%Y-%m-%d %H:%M' )
            ip_version = 'IPv4' if stat_tuple[ 2 ] == '4' else 'IPv6'
            ( src, dst ) = stat_tuple[ 3:5 ]
            count = int( stat_tuple[ -1 ] )
            counts[ ip_version ][ timestamp ] = counts[ ip_version ].get( timestamp, 0 ) + count
            domain = resolve_domain( src, dst, resolved, unresolved, ignored )
            if domain:
                if domain not in domain_counts:
                    domain_counts[ domain ] = { 'IPv4': 0, 'IPv6': 0 }
                domain_counts[ domain ][ ip_version ] += count

    # Set up plot
    _, ( ax_count, ax_domainwise ) = plt.subplots( 2, 1 )
    plt.ion()
    plt.get_current_fig_manager().full_screen_toggle()
    # Plot 1: IPv4 and IPv6 packet counts vs Time
    for ip_version, color in zip( counts.keys(), ( 'blue', 'green' )):
        ax_count.plot( counts[ ip_version ].keys(), counts[ ip_version ].values(), color=color, label=ip_version )
    ax_count.set_title( 'IPv4 and IPv6 packet counts vs Time' )
    ax_count.set_xlabel( 'Timestamp' )
    ax_count.set_ylabel( '# of packets sent/received' )
    ax_count.xaxis.set_major_formatter( dates.DateFormatter( '%Y-%m-%d %H:%M' ) )
    ax_count.xaxis.set_major_locator( dates.AutoDateLocator() )
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
    # Text outputs
    ipv4_total = sum( [ count for count in counts[ 'IPv4' ].values() ] )
    ipv6_total = sum( [ count for count in counts[ 'IPv6' ].values() ] )
    ipv4_pct = 100 * ipv4_total / ( ipv4_total + ipv6_total )
    print( f"Percentage breakdown of traffic: IPv4: {ipv4_pct: .2f}, IPv6: {( 100 - ipv4_pct ): .2f}" )
    plt.draw()
    plt.waitforbuttonpress()
    sys.exit( 0 )

if __name__ == "__main__":
    main()