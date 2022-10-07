from argparse import ArgumentParser
from operator import itemgetter
import sys
from typing import Optional
from datetime import datetime

import matplotlib.pyplot as plt
from matplotlib import dates
import numpy
from tqdm import tqdm

from socket import gethostbyaddr
from ipaddress import ip_address
from pyasn import pyasn

def get_parser() -> ArgumentParser:
    parser = ArgumentParser( description="IP-Version-Stats: A tool to monitor network traffic and obtain IPv4 vs IPv6 traffic statistics." )

    # Arguments
    parser.add_argument( '-o', '--outpath', dest='outpath',
                         default='stats.txt', type=str,
                         help="Path to the output file created by the sniffer tool. Default: <pwd>/stats.txt" )
    parser.add_argument( '-rt', '--require-transport', dest='require_transport',
                         default=False, action='store_true',
                         help="Only consider TCP/UDP flows" )
    parser.add_argument( '-iip', '--ignore-ip', dest='ignored_ips',
                         nargs='+', type=str, default=[],
                         help="IP(v4/v6) addresses to ignore while resolving" )
    parser.add_argument( '-idom', '--ignore-domain', dest='ignored_domains',
                         nargs='+', type=str, default=[],
                         help="Domains to ignore while resolving" )
    parser.add_argument( '-ias', '--ignore-as', dest='ignored_as',
                         nargs='+', type=int, default=[],
                         help="AS numbers to ignore while resolving" )

    return parser

def _resolve_domain( addr: str, ignored_domains: list[ str ] ):
    try:
        if ip_address( addr ).is_private:
            return None
        result = gethostbyaddr( addr )
        result_split = result[ 0 ].split( '.' )
        if len( result_split ) > 1: # Assuming there can be no useful domains without a '.', eg: 'ipv6-allnodes'
            result_domain = result_split[ -2 ] + '.' + result_split[ -1 ]   # 123.foo-bar.xyz.com -> xyz.com
            if result_domain not in ignored_domains:
                return result_domain
        return None
    except OSError:
        return None

def resolve( from_addr: str, to_addr: str,
             ignored_ips: list[ str ],
             domain_resolved_ips: dict[ str, Optional[ str ] ], domain_unresolved_ips: list[ str ], ignored_domains: list[ str ],
             as_db: pyasn, ignored_as: list[ int ] ):
    resolved_domain: str = None
    resolved_as: int = None

    # Resolve domain
    if from_addr in domain_resolved_ips:
        resolved_domain = domain_resolved_ips[ from_addr ]
    elif to_addr in domain_resolved_ips:
        resolved_domain = domain_resolved_ips[ to_addr ]
    else:
        for addr in ( from_addr, to_addr ):
            if ( addr not in ignored_ips ) and ( addr not in domain_unresolved_ips ):
                result = _resolve_domain( addr, ignored_domains )
                if result:
                    resolved_domain = result
                    domain_resolved_ips[ addr ] = resolved_domain
                else:
                    domain_unresolved_ips.append( addr )

    # Resolve AS
    for addr in ( from_addr, to_addr ):
        if ip_address( addr ).is_private or ( addr in ignored_ips ):
            continue
        ( asn, _ ) = as_db.lookup( addr )
        if ( asn is not None ) and ( asn not in ignored_as ):
            resolved_as = asn
    
    return ( resolved_domain, resolved_as )

def main():
    # Parse command line arguments
    parser = get_parser()
    args = parser.parse_args()

    counts = { 'IPv4': {}, 'IPv6': {} }
    domain_resolved_ips = {}    # Cache of resolved IPs
    domain_unresolved_ips = []  # Tried resolving but failed
    domain_counts: dict[ str, dict ] = {}
    as_counts: dict[ int, dict ] = {}
    as_db = pyasn( 'as.db' )
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
            ( domain, asn ) = resolve( src, dst,
                                       args.ignored_ips,
                                       domain_resolved_ips, domain_unresolved_ips, args.ignored_domains,
                                       as_db, args.ignored_as )
            if domain:
                if domain not in domain_counts:
                    domain_counts[ domain ] = { 'IPv4': 0, 'IPv6': 0 }
                domain_counts[ domain ][ ip_version ] += count
            if asn:
                if asn not in as_counts:
                    as_counts[ asn ] = { 'IPv4': 0, 'IPv6': 0 }
                as_counts[ asn ][ ip_version ] += count

    # Set up plot
    _, ( ax_count, ax_domainwise, ax_aswise ) = plt.subplots( 3, 1 )
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
    # Plot 3: IPv4 vs IPv6 stats for Autonomous Systems with highest traffic
    as_totals = sorted( { asn: sum( counts.values() ) for asn, counts in as_counts.items() }.items(),
                        key=itemgetter( 1 ),
                        reverse=True )[ :10 ]
    x_values = [ entry[ 0 ] for entry in as_totals ]
    y_values_ipv4 = [ as_counts[ entry[ 0 ] ][ 'IPv4' ] for entry in as_totals ]
    y_values_ipv6 = [ as_counts[ entry[ 0 ] ][ 'IPv6' ] for entry in as_totals ]
    x_points = numpy.arange( len( x_values ) )
    ax_aswise.bar( x_points - 0.2, y_values_ipv4, width=0.2, color='b', align='edge', label='IPv4' )
    ax_aswise.bar( x_points, y_values_ipv6, width=0.2, color='g', align='edge', label='IPv6' )
    ax_aswise.set_xticks( x_points, x_values )
    ax_aswise.set_title( 'IPv4 vs IPv6 stats for Autonomous Systems with the highest traffic' )
    ax_aswise.set_xlabel( 'ASN' )
    ax_aswise.set_ylabel( '# of packets sent/received' )
    ax_aswise.legend( loc='upper right' )
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