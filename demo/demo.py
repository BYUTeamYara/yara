#Runs Yara and Hyperscan multiple times to compare.

import os
import time

runTimes=10
totalTime=0

for i in range(runTimes):
    start=time.time()
    os.system("yara test.yara syslog | grep null")
    end=time.time()
    totalTime+=end-start

totalTime=totalTime/runTimes
print("Average Yara time: " + str(totalTime) + " seconds.")
totalTime=0

for i in range(runTimes):
    start=time.time()
    os.system("./simplegrep C3HQS750B syslog | grep null")
    end=time.time()
    totalTime+=end-start

totalTime=totalTime/runTimes
print("Average Hyperscan time: " + str(totalTime) + " seconds.")
