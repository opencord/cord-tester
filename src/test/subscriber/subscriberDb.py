
# Copyright 2017-present Open Networking Foundation
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
import sqlite3
import sys

class SubscriberDB:

    default_services = ('TLS', 'DHCP', 'IGMP')

    def __init__(self, db = 'subscriber.db', create = False, services = default_services):
        self.db = db
        self.con = sqlite3.connect(db)
        self.con.row_factory = sqlite3.Row
        self.cur = self.con.cursor()
        self.services = services
        self.create = create
        if create == True:
            self.cur.execute("DROP TABLE IF EXISTS Subscriber")
            self.cur.execute("CREATE TABLE Subscriber(Id INTEGER PRIMARY KEY, Name TEXT, Service TEXT);")

    def load(self, name, service):
        self.cur.execute("INSERT INTO Subscriber(Name, Service) VALUES (?, ?);", (name, service))

    def commit(self):
        self.con.commit()

    def generate(self, num = 100):
        #create db if not created
        if self.create is False:
            self.cur.execute("DROP TABLE IF EXISTS Subscriber")
            self.cur.execute("CREATE TABLE Subscriber(Id INTEGER PRIMARY KEY, Name TEXT, Service TEXT);")
            self.create = True
        service = ' '.join(self.services)
        for i in xrange(num):
            name = "sub%d" %self.lastrowid()
            self.load(name, service)
        self.commit()

    def read(self, num = 1000000, debug = False):
        self.cur.execute("SELECT * FROM Subscriber LIMIT ?;", (num,))
        rows = self.cur.fetchall()
        if debug is True:
            for row in rows:
                print('Id %d, Name %s, Service %s' %(row['Id'], row['Name'], row['Service']))
        return rows

    def lastrowid(self):
        return 0 if self.cur.lastrowid == None else self.cur.lastrowid

if __name__ == "__main__":
    create = False
    if len(sys.argv) > 1:
        try:
            num_subscribers = int(sys.argv[1])
        except:
            num_subscribers = 100
        print('Creating %d subscriber records' %num_subscribers)
        create = True
    sub = SubscriberDB(create = create)
    if create == True:
        sub.generate(num_subscribers)
    else:
        num_subscribers = 10
    subscribers = sub.read(num_subscribers)
    for s in subscribers:
        print('Name %s, Service %s' %(s['Name'], s['Service']))
