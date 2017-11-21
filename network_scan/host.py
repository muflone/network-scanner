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
        self.netbios_name = ''
        self.netbios_group = ''

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

    def netbios(self):
        """Launch nmblookup to the current host"""
        arguments = ['nmblookup', '-A', '-S', self.address]
        process = Process(arguments)
        for line in process.run().split('\n'):
            # <00> Identifies the workstation
            if '<00>' in line:
                if '<GROUP>' in line:
                    self.netbios_group = line.split('<')[0].strip()
                else:
                    self.netbios_name = line.split('<')[0].strip()

    def scan(self):
        """Execute scan"""
        self.fqdn = socket.getfqdn(self.address)
        self.arping()
        if self.mac:
            self.netbios()
        return self.mac or self.netbios_name or self.netbios_group
