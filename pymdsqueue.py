# Copyright (c) 2009 Tom Pinckney
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
#     The above copyright notice and this permission notice shall be
#     included in all copies or substantial portions of the Software.
#
#     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#     EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
#     OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#     NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT


#
# A pymds source filter.

import struct
from utils import *
from altautils.kawaiiqueue import KawaiiQueueClient
import os.path
import pickle

class Source(object):

    def __init__(self, name, host, port, data_cache_path):
        self._answers = {}
        self.name = name
        self.host = host
        self.port = port
        self.data_cache_path = data_cache_path
        self.update_from_cache()
        self.update()

    def update(self):
        """
        read new msgs off the queue
        """

        print 'updating from queue: %s %s %s' % (self.name,
                                                 self.host,
                                                 self.port)

        queue = KawaiiQueueClient(self.name,
                                  self.host,
                                  self.port)

        updated = False
        for qmsg in queue:
            
            updated = True
            
            question = qmsg.body.get('question')
            _type = qmsg.body.get('type')
            value = qmsg.body.get('value')

            question = question.lower()
            _type = _type.upper()

            print 'qmsg: %s %s %s %s' % (qmsg.label,question,_type,value)

            if question == '@':
                question = ''
            if _type == 'A':
                answer = struct.pack("!I", ipstr2int(value))
                qtype = 1
            if _type == 'NS':
                answer = labels2str(value.split("."))
                qtype = 2
            elif _type == 'CNAME':
                answer = labels2str(value.split("."))
                qtype = 5
            elif _type == 'TXT':
                answer = label2str(value)
                qtype = 16
            elif _type == 'MX':
                preference, domain = value.split(":")
                answer = struct.pack("!H", int(preference))
                answer += labels2str(domain.split("."))
                qtype = 15

            answers = self._answers.setdefault(question, {}).setdefault(qtype, [])

            # are we adding or removing
            if qmsg.label.lower() == 'remove':
                print 'removing'
                try:
                    answers.remove(answer)
                except IndexError:
                    print 'answer wasnt in answer'

            else:
                print 'adding'
                if answer not in answers:
                    answers.append(answer)
                else:
                    print 'already exists'

        if updated:
            self.update_cache()


    def update_cache(self):
        print 'updating cache'
        with file(self.data_cache_path,'w') as fh:
            fh.write(pickle.dumps(self._answers))

    def update_from_cache(self):
        if os.path.exists(self.data_cache_path):
            with file(self.data_cache_path,'r') as fh:
                self._answers = pickle.loads(fh.read())
        
        

    def get_response(self, query, domain, qtype, qclass, src_addr):
        print 'source query: %s %s %s %s %s' % (query,domain,qtype,qclass,src_addr)

        if query not in self._answers:
            return 3, []
        if qtype in self._answers[query]:
            results = [{'qtype': qtype, 'qclass':qclass, 'ttl': 500, 'rdata': answer} for answer in self._answers[query][qtype]]
            print 'results: %s' % results
            return 0, results
        elif qtype == 1:
            # if they asked for an A record and we didn't find one, check for a CNAME
            return self.get_response(query, domain, 5, qclass, src_addr)
        else:
            return 3, []
