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

import socket
import multiprocessing

from network_scan.process import Process

class Host(object):
    def __init__(self, index, address):
        self.index = index
        self.address = address
        self.mac = ''
        self.fqdn = ''

    def arping(self):
        arguments = ['arping', '-f', '-c', '1', '-I', 'eth0', self.address]
        process = Process(arguments)
        for line in process.run().split('\n'):
            if 'reply' in line:
                self.mac = line.split('[')[1].split(']')[0]
                return True
        else:
            return False

    def scan(self):
        self.fqdn = socket.getfqdn(self.address)
        self.arping()
        return self.mac

    def __repr__(self):
        return ('{:<15}  {:<17}'.format(self.address, self.mac))

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return False


def consume(working_queue, done_queue):
    """Cycle the working queue for each worker until the 'STOP' is found"""
    for host in iter(working_queue.get, 'STOP'):
        if host.scan():
            # Add results to the done queue
            done_queue.put(host)
    return True

if __name__ == '__main__':
    if not Host(0, 'localhost').arping():
        print 'Unable to detect localhost, maybe arping lacks permissions?'
    else:
        # Scan network
        max_workers = 10
        subnet = '192.168.1'
        working_queue = multiprocessing.Queue()
        done_queue = multiprocessing.Queue()
        for host in xrange(1, 70 + 1):
            address = '%s.%d' % (subnet, host)
            # Add the host scanner to the working queue
            working_queue.put(Host(host, address))
        # Consume processes
        processes = []
        for worker in xrange(max_workers):
            process = multiprocessing.Process(target=consume,
                                              args=(working_queue,
                                                    done_queue))
            # Add a consumer process to the queue
            process.start()
            processes.append(process)
            # Add an end-of-loop sentinel for iter for each worker
            working_queue.put('STOP')
        # Wait for completion
        for process in processes:
            process.join()
        # Add an end-of-loop sentinel for the done work queue
        done_queue.put('STOP')

        # Print headers results
        with Host(0, 'IP Address') as host:
            host.mac = 'MAC Address'
            host.fqdn = 'Fully qualified domain name'
            print host
            print '-' * 80
        # Print sorted results, waiting for the end-of-loop sentinel
        for status in sorted(iter(done_queue.get, 'STOP'),
                             key=lambda host: host.index):
            print status
