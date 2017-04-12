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
class CordTester(object):

    def __init__(self, fsmTable, stopState, stateTable = None, eventTable = None):
        self.fsmTable = fsmTable
        self.stopState = stopState
        self.stateTable = stateTable
        self.eventTable = eventTable
        self.currentState = None
        self.currentEvent = None
        self.nextState = None
        self.nextEvent = None

    def runTest(self):
        while self.currentState != self.stopState and self.currentEvent != None:
            if self.stateTable and self.eventTable:
                print('Current state: %s, Current event: %s' %(self.stateTable.toStr(self.currentState),
                                                               self.eventTable.toStr(self.currentEvent)))
            key = (self.currentState, self.currentEvent)
            (actions, nextState) = self.fsmTable[key]
            if actions:
                for a in actions:
                    a()
            self.currentState = nextState if self.nextState is None else self.nextState
            self.currentEvent = self.nextEvent
