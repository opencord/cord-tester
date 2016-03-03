from math import sqrt

class Stats:
      def __init__(self):
            self.count = 0
            self.start = 0
            self.delta = 0
            self.min = 0
            self.max = 0
            self.delta_squares = 0

      def update(self, packets = 0, t = 0):
            self.count += packets
            t *= 1000000 ##convert to usecs
            if self.start == 0:
                  self.start = t
            self.delta += t
            self.delta_squares += t*t
            if self.min == 0 or t < self.min:
                  self.min = t
            if self.max == 0 or t > self.max:
                  self.max = t

      def __repr__(self):
            if self.count == 0:
                  self.count = 1
            mean = self.delta/self.count
            mean_square = mean*mean
            delta_square_mean = self.delta_squares/self.count
            std_mean = sqrt(delta_square_mean - mean_square)
            r = 'Avg %.3f usecs, Std deviation %.3f usecs, Min %.3f, Max %.3f for %d packets\n' %(
                  mean, std_mean, self.min, self.max, self.count)
            return r

