#Runs Yara and Hyperscan multiple times to compare.
#Written by Max Parkinson and Jackson Flood

import os
import time

runTimes=10
totalTime=0

#runs Yara number of times and gets average time.
#test.yara can be edited depending on the rule that you want to use.
print("Testing Yara...")
for i in range(runTimes):
    start=time.time()
    os.system("yara test.yara syslog | grep null")
    end=time.time()
    totalTime+=end-start

totalTime=totalTime/runTimes
print("Average Yara time:         " + str(totalTime) + " seconds.")
totalTime=0

#runs Hyperscan simplegrep program and gets average time.
print("Testing Hyperscan...")
for i in range(runTimes):
    start=time.time()
    os.system("./simplegrep C3HQS750B syslog | grep null")
    end=time.time()
    totalTime+=end-start

totalTime=totalTime/runTimes
print("Average Hyperscan time:    " + str(totalTime) + " seconds.")
