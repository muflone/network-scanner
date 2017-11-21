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

import multiprocessing

from host import Host


class Scanner(object):
    """Scan a subnet using Host's methods"""
    def __init__(self, subnet, starting_host, ending_host):
        self.working_queue = multiprocessing.Queue()
        self.done_queue = multiprocessing.Queue()
        for host in xrange(starting_host, ending_host + 1):
            address = '%s.%d' % (subnet, host)
            # Add the host scanner to the working queue
            self.working_queue.put(Host(host, address))

    def __consume(self, working_queue, done_queue):
        """Cycle the working queue for each worker until the 'STOP' is found"""
        for host in iter(working_queue.get, 'STOP'):
            if host.scan():
                # Add results to the done queue
                done_queue.put(host)
        return True

    def start(self, max_workers):
        """Launch real workers for scan"""
        processes = []
        for worker in xrange(max_workers):
            process = multiprocessing.Process(target=self.__consume,
                                              args=(self.working_queue,
                                                    self.done_queue))
            # Add a consumer process to the queue
            process.start()
            processes.append(process)
            # Add an end-of-loop sentinel for iter for each worker
            self.working_queue.put('STOP')
        # Wait for completion
        for process in processes:
            process.join()
        # Add an end-of-loop sentinel for the done work queue
        self.done_queue.put('STOP')
