#!/usr/bin/env python2
##
#     Project: Network Scanner
# Description: Network scanner based on external tools
#      Author: Fabio Castelli (Muflone) <muflone@vbsimple.net>
#   Copyright: 2017 Fabio Castelli
#     License: GPL-2+
#  This program is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by the Free
#  Software Foundation; either version 2 of the License, or (at your option)
#  any later version.
#
#  This program is distributed in the hope that it will be useful, but WITHOUT
#  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
#  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
#  more details.
#  You should have received a copy of the GNU General Public License along
#  with this program; if not, write to the Free Software Foundation, Inc.,
#  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
##


from network_scan.host import Host
from network_scan.scanner import Scanner


# Launch scan when called from main script
if __name__ == '__main__':
    if not Host(0, 'localhost').arping():
        print 'Unable to detect localhost, maybe arping lacks permissions?'
    else:
        # Scan network
        scanner = Scanner(subnet='192.168.1',
                          starting_host=1,
                          ending_host=70)
        scanner.start(max_workers=10)

        # Print headers results
        with Host(0, 'IP Address') as host:
            host.mac = 'MAC Address'
            host.netbios_name = 'NBT NAME'
            host.netbios_group = 'NBT GROUP'
            host.fqdn = 'Fully qualified domain name'
            print host
            print '-' * 100
        # Print sorted results, waiting for the end-of-loop sentinel
        for status in sorted(iter(scanner.done_queue.get, 'STOP'),
                             key=lambda host: host.index):
            print status
