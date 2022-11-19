from argparse import ArgumentParser
import pickle
from pprint import pprint

def get_parser() -> ArgumentParser:
    parser = ArgumentParser( description="IP-Version-Stats: A tool to monitor network traffic and obtain IPv4 vs IPv6 traffic statistics." )

    # Arguments
    parser.add_argument( '-o', dest='out_path', type=str, required=True,
                         help="Path to the output pickle file generated by analysis.py" )

    return parser

def main():
    # Parse command line arguments
    parser = get_parser()
    args = parser.parse_args()

    with open( args.out_path, 'rb' ) as outfile:
        ( _, _, _, interval_stats, _, _ ) = pickle.load( outfile )

    domains = {}
    asns = {}

    THRESHOLD = 0.85

    for entry in interval_stats.values():
        for protocol, protocol_domain in entry[ 'domains' ].items():
            for domain, count in protocol_domain.items():
                if domain not in domains:
                    domains[ domain ] = { 'v4TCP': 0, 'v4UDP': 0, 'v6TCP': 0, 'v6UDP': 0 }
                domains[ domain ][ protocol ] += count
        for protocol, protocol_as in entry[ 'as' ].items():
            for asn, count in protocol_as.items():
                if asn not in asns:
                    asns[ asn ] = { 'v4TCP': 0, 'v4UDP': 0, 'v6TCP': 0, 'v6UDP': 0 }
                asns[ asn ][ protocol ] += count

    # TCP
    tcpLeaderDomains = {}
    tcpLaggardDomains = {}
    for domain, counts in domains.items():
        if ( ( counts[ 'v4TCP' ] + counts[ 'v6TCP' ] ) == 0 ):
            continue
        v6frac = ( counts[ 'v6TCP' ] / ( counts[ 'v4TCP' ] + counts[ 'v6TCP' ] ) )
        if ( v6frac >= THRESHOLD ):
            tcpLeaderDomains[ domain ] = counts[ 'v6TCP' ]
        elif ( v6frac <= ( 1 - THRESHOLD ) ):
            tcpLaggardDomains[ domain ] = counts[ 'v4TCP' ]

    tcpLeaderAs = {}
    tcpLaggardAs = {}
    for asn, counts in asns.items():
        if ( ( counts[ 'v4TCP' ] + counts[ 'v6TCP' ] ) == 0 ):
            continue
        v6frac = ( counts[ 'v6TCP' ] / ( counts[ 'v4TCP' ] + counts[ 'v6TCP' ] ) )
        if ( v6frac >= THRESHOLD ):
            tcpLeaderAs[ asn ] = counts[ 'v6TCP' ]
        elif ( v6frac <= ( 1 - THRESHOLD ) ):
            tcpLaggardAs[ asn ] = counts[ 'v4TCP' ]

    print( "Leader Domains (TCP): " )
    print( { k: v for k, v in sorted( tcpLeaderDomains.items(), reverse=True,  key=lambda item: item[ 1 ] ) } )
    print( "\nLeader ASNs (TCP):" )
    print( { k: v for k, v in sorted( tcpLeaderAs.items(), reverse=True,  key=lambda item: item[ 1 ] ) } )
    print( "\nLaggard Domains (TCP):" )
    print( { k: v for k, v in sorted( tcpLaggardDomains.items(), reverse=True,  key=lambda item: item[ 1 ] ) } )
    print( "\nLaggard ASNs (TCP):" )
    print( { k: v for k, v in sorted( tcpLaggardAs.items(), reverse=True,  key=lambda item: item[ 1 ] ) } )

    # UDP
    udpLeaderDomains = {}
    udpLaggardDomains = {}
    for domain, counts in domains.items():
        if ( ( counts[ 'v4UDP' ] + counts[ 'v6UDP' ] ) == 0 ):
            continue
        v6frac = ( counts[ 'v6UDP' ] / ( counts[ 'v4UDP' ] + counts[ 'v6UDP' ] ) )
        if ( v6frac >= THRESHOLD ):
            udpLeaderDomains[ domain ] = counts[ 'v6UDP' ]
        elif ( v6frac <= ( 1 - THRESHOLD ) ):
            udpLaggardDomains[ domain ] = counts[ 'v4UDP' ]

    udpLeaderAs = {}
    udpLaggardAs = {}
    for asn, counts in asns.items():
        if ( ( counts[ 'v4UDP' ] + counts[ 'v6UDP' ] ) == 0 ):
            continue
        v6frac = ( counts[ 'v6UDP' ] / ( counts[ 'v4UDP' ] + counts[ 'v6UDP' ] ) )
        if ( v6frac >= THRESHOLD ):
            udpLeaderAs[ asn ] = counts[ 'v6UDP' ]
        elif ( v6frac <= ( 1 - THRESHOLD ) ):
            udpLaggardAs[ asn ] = counts[ 'v4UDP' ]

    print( "\nLeader Domains (UDP): " )
    print( { k: v for k, v in sorted( udpLeaderDomains.items(), reverse=True,  key=lambda item: item[ 1 ] ) } )
    print( "\nLeader ASNs (UDP):" )
    print( { k: v for k, v in sorted( udpLeaderAs.items(), reverse=True,  key=lambda item: item[ 1 ] ) } )
    print( "\nLaggard Domains (UDP):" )
    print( { k: v for k, v in sorted( udpLaggardDomains.items(), reverse=True,  key=lambda item: item[ 1 ] ) } )
    print( "\nLaggard ASNs (UDP):" )
    print( { k: v for k, v in sorted( udpLaggardAs.items(), reverse=True,  key=lambda item: item[ 1 ] ) } )

if __name__ == "__main__":
    main()