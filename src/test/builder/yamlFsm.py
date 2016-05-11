# 
# Copyright 2016-present Ciena Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import yaml, pprint, sys, pdb

stateHash = {}
header = '''#!/usr/bin/env python
'''
# ---------------------------- DOT -----------------------------------
colorList = ['aquamarine4', 'crimson', 'chartreuse4', 'darkolivegreen', 'darkgoldenrod', 'dodgerblue3', 'blue4', 'cyan4']
rankdict = {}
# ---------------------------- DOT -----------------------------------

if __name__ == '__main__':

    usage = ''
    from optparse import OptionParser
    parser = OptionParser(usage)
    parser.add_option('-p', '--prefix', dest='prefix', type='string', action='store', help='prefix for state table')
    parser.add_option('-f', '--file', dest='file', type='string', action='store', help='input yaml filename')
    parser.add_option('-d', '--dot', dest='dot', default=False, action='store_true', help='output DOT')
    (opts, args) = parser.parse_args()
    prefix = opts.prefix
    f = open(opts.file, 'r')
    y = yaml.load(f)
    f.close()
    stateHash = y['States']
    eventHash = {}
    # GLOBAL DOT DIRECTIVES
    stateRadiate        = y.get('DOT_StateRadiate')
    ignoredIntensity    = abs(int(y.get('DOT_IgnoredIntensity', 100)) - 100)
    eventGroups         = y.get('DOT_EventGroups')
    if stateRadiate is not None:
        stateRadiate = str(stateRadiate)

    actionStrLen = [0]
    stateColorIdx = 0
    for k, v in stateHash.iteritems():
        events = v.get('Events')
        if events:
            for event in events.keys():
                eventHash[event] = {}
            actionStr = ''
            for ev in events.values():
                if ev.get('Actions'):
                    actionStr = ','.join(['obj.%s' % action for action in ev['Actions']]) + ','
                    actionStrLen.append(len(actionStr))
            
        ievents = v.get('IgnoredEvents')
        if ievents:
            for event in ievents.keys():
                eventHash[event] = {}

        # ---------------------------- DOT -----------------------------------
        # rankdict setup
        rank = v.get('DOT_Rank')
        if rank:
            print >>sys.stderr, '%s rank %s' % (k, str(rank)) 
            rankdict.setdefault(rank, []).append(k)

        # assign a possible color if not specified
        color = v.get('DOT_Color')
        if color:
            print >>sys.stderr, 'using user assigned color %s for %s' % (color, k)
        else:            
            if stateRadiate and stateRadiate.lower() == 'auto':
                color = colorList[stateColorIdx % len(colorList)]
                stateColorIdx+= 1
            else:
                color = 'black'
                
        stateHash[k]['DOT_Color'] = color
        # ---------------------------- DOT -----------------------------------        

    # ---------------------------- DOT -----------------------------------
    # update the event hash with information from the event groups (if present)
    if eventGroups:
        for group in eventGroups.values():
            for event in group['Events'].keys():
                for attr, val in group['Attrs'].iteritems():
                    eventHash[event][attr] = val
                    print >>sys.stderr, 'assigning event group attr event %s attr %s val %s' % (event, attr, val)
    # ---------------------------- DOT -----------------------------------

    maxStateLen = reduce(max, [len(x) for x in stateHash.keys()]) + 5 + len(prefix) 
    maxEventLen = reduce(max, [len(x) for x in eventHash.keys()]) + 5 + len(prefix)
    maxActionLen = reduce(max, actionStrLen) + 5

    if opts.dot:
        print 'digraph G {'
        print ' edge  [fontname="Tahoma", fontsize="10", minlen=2];'
        print ' node  [fontname="Tahoma", fontsize="10"];'
        print ' graph [fontname="Tahoma", label="%s"];' % prefix
        print >>sys.stderr, 'stateRadiate:%s\nignoredIntensity:%d' % (stateRadiate, ignoredIntensity)
        
        # emit state declarations
        for state in stateHash.keys():
            print ' %s[color="%s"];' % (state, stateHash[state]['DOT_Color'])

        # emit rankings        
        for k, v in rankdict.iteritems():
            print >>sys.stderr, '%s rank %s' % (k, str(v)) 

            print 'subgraph { rank = same;'
            for state in v:
                    print ' %s;' % state 
            print '}'
            
        for state, va in stateHash.iteritems():
            # emit ignored events
            if va.get('IgnoredEvents'):
                for event, v in va['IgnoredEvents'].iteritems():
                    stateStr = state
                    eventStr = event
                    print '%s -> %s [label="%s/",minlen=1, fontcolor="grey%d", color="grey%d"];' % (stateStr, stateStr, eventStr, ignoredIntensity, ignoredIntensity)

            # emit transitions
            if va.get('Events'):
                for event, v in va['Events'].iteritems():
                    stateStr = state
                    eventStr = event
                    actionStr = ''
                    if v.get('Actions'):
                        actionStr = '\\n'.join([a.strip('_') for a in v['Actions']])
                    nextStr = v['NextState']
                    labelStr = '%s/\\n%s' % (eventStr, actionStr)
                    if stateRadiate:
                        color = va['DOT_Color']
                    elif len(eventHash[event]):
                        color = eventHash[event]['Color']
                    else:
                        color = 'black'

                    fontColor = color
                    styleStr = ''
                    style = eventHash[event].get('Style')
                    if style:
                        styleStr = ',style="%s"' % (style)

                        if style == 'invis':
                            fontColor = 'white'
                        
                    print '%s -> %s [label="%s", color="%s", fontcolor="%s" %s];' % (stateStr, nextStr, labelStr, color, fontColor, styleStr)
                
            print

        print '}'

    else:
    
### emit it

        print header

### enumerations
        '''
        print '%sSt = Enumeration("%sState",(' % (prefix, prefix)
        for state in stateHash.keys():
            print '%s"%s",' % (' '*12, state)
        print '%s))' % (' '*12)

        print 
        
        print '%sEv = Enumeration("%sEvent",(' % (prefix, prefix)
        for event in eventHash.keys():
            print '%s"%s",' % (' '*12, event)
        print '%s))' % (' '*12)
        '''
### table

        fmt = '      (%' + '-%d.%ds' % (maxStateLen, maxStateLen) + '%' + '-%d.%ds' % (maxEventLen, maxEventLen) + '):( %' +' -%d.%ds' % (maxActionLen, maxActionLen) + '%s),' 
        cfmt= '    ## %' + '-%d.%ds' % (maxStateLen, maxStateLen) + '%' + '-%d.%ds' % (maxEventLen, maxEventLen) + '    %' +' -%d.%ds' % (maxActionLen, maxActionLen) + '%s' 

        print 'def init%s%sFsmTable(obj,St,Ev):' % (prefix[0].upper(), prefix[1:])
#        print "    %sFsmTable = {" % prefix
        print "    return {"
        print
        
        for state, va in stateHash.iteritems():

            print cfmt % ('CurrentState', 'Event', 'Actions', 'NextState')
            print

            if va.get('IgnoredEvents'):
                for event, v in va['IgnoredEvents'].iteritems():
                    stateStr = '%sSt.' % ('') + state + ','
                    eventStr = '%sEv.' % ('') + event
                
                    print fmt % (stateStr, eventStr, '(),', stateStr.strip(','))

            if va.get('Events'):
                for event, v in va['Events'].iteritems():
                    stateStr = '%sSt.' % ('') + state + ','
                    eventStr = '%sEv.' % ('') + event
                    actionStr = ''
                    if v.get('Actions'):
                        actionStr = ','.join(['obj.%s' % action for action in v['Actions']]) + ','
                                        
                    nextStr = '%sSt.' % ('') + v['NextState']
                    
                    print fmt % (stateStr, eventStr, '(%s),' % actionStr , nextStr)

            print
        
        print "}"    
        print    


