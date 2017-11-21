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


class IEEE_OUI(object):
    """
    IEEE OUI database with MAC address and vendor associations
    Source:
        https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf;hb=HEAD
    """
    def __init__(self):
        self.db_oui = {}

    def load(self, file_path):
        """Load IEEE OUI database"""
        with open(file_path, 'r') as file_oui:
            for line in file_oui:
                # Strip comments
                if '#' in line:
                    line = line.split('#', 1)[0]
                line = line.strip()
                if line:
                    # Always use the last field
                    parts = line.split('\t')
                    manufacturer = parts[-1]
                    oui = parts[0][:8]
                    self.db_oui[oui] = manufacturer

    def get(self, oui):
        """Return the vendor associated to the OUI"""
        return self.db_oui.get(oui, '')
