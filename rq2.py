from argparse import ArgumentParser
import pickle
from pprint import pprint

def get_parser() -> ArgumentParser:
    parser = ArgumentParser( description="IP-Version-Stats: A tool to monitor network traffic and obtain IPv4 vs IPv6 traffic statistics." )

    # Arguments
    parser.add_argument( '-o', dest='out_path', type=str, required=True,
                         help="Path to the output pickle file generated by analysis.py" )
    parser.add_argument( '-tb', dest='threshold_bytes', type=int, default=104857600,    # default = 100MB
                         help="Threshold in bytes for an interval to be considered of interest" )
    parser.add_argument( '-tp', dest='threshold_packets', type=int, default=50000,
                         help="Threshold in number of packets for an interval to be considered of interest" )

    return parser

def main():
    # Parse command line arguments
    parser = get_parser()
    args = parser.parse_args()

    with open( args.out_path, 'rb' ) as outfile:
        ( _, _, delta_counts, interval_stats, _, _ ) = pickle.load( outfile )

    for proto in ( 'v4_tcp_txrx', 'v4_udp_txrx', 'v6_tcp_txrx', 'v6_udp_txrx' ):
        print( 'Intervals of interest for ' + proto + ':' )
        for timestamp, entry in delta_counts.items():
            if ( entry[ proto ][ 0 ] >= args.threshold_packets ) or ( entry[ proto ][ 1 ] >= args.threshold_bytes ):
                print( timestamp )
                if entry[ proto ][ 0 ] >= args.threshold_packets:
                    print( "Reason for interest: Packet count >= " + str( args.threshold_packets ) )
                if entry[ proto ][ 1 ] >= args.threshold_bytes:
                    print( "Reason for interest: Bytes >= " + str( args.threshold_bytes ) )
                pprint( entry, indent=4 )
                pprint( interval_stats[ timestamp ], indent=4 )
                print()
        print()


if __name__ == "__main__":
    main()