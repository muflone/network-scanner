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

import socket

from process import Process


class Host(object):
    """Define a host to scan"""
    def __init__(self, index, address):
        self.index = index
        self.address = address
        self.mac = ''
        self.fqdn = ''

    def arping(self):
        """Launch arping to the current host"""
        arguments = ['arping', '-f', '-c', '1', '-I', 'eth0', self.address]
        process = Process(arguments)
        for line in process.run().split('\n'):
            if 'reply' in line:
                self.mac = line.split('[')[1].split(']')[0]
                return True
        else:
            return False

    def scan(self):
        """Execute scan"""
        self.fqdn = socket.getfqdn(self.address)
        self.arping()
        return self.mac

    def __repr__(self):
        """Format results"""
        return ('{:<15}  {:<17}'.format(self.address, self.mac))

    def __enter__(self):
        """Enter for with"""
        return self

    def __exit__(self, type, value, traceback):
        """Exit for with"""
        return False
