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
                print 'Current state: %s, Current event: %s' %(self.stateTable.toStr(self.currentState),
                                                               self.eventTable.toStr(self.currentEvent))
            key = (self.currentState, self.currentEvent)
            (actions, nextState) = self.fsmTable[key]
            if actions:
                for a in actions:
                    a()
            self.currentState = nextState
            self.currentEvent = self.nextEvent
