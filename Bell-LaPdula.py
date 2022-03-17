# Danny Habash
# CSCE 3550.001
# 2/23/2022
# Description: reads instructions from a file and creates a Bell-LaPadula security system

import sys


#subject class with name and value initialized to 0, contains getters and setter for both attributes
class Subject:
    def __init__(self, name, value=0):
        self.name = name
        self.value = value
    
    def getName(self):
        return self.name

    def setName(self,name):
        self.name = name

    def getValue(self):
        return self.value

    def setValue(self, val):
        self.value = val

#object class with name and value initialized to 0, contains getters and setter for both attributes
class Object:
    def __init__(self, name, value=0):
        self.name = name
        self.value = value
    
    def getName(self):
        return self.name

    def setName(self,name):
        self.name = name

    def getValue(self):
        return self.value

    def setValue(self, val):
        self.value = val

#reference monitor class that controls read and write operations
class RefMon:
    #converts security levels to integer values for ease of use
    levels={
        "low": 1,
        "medium": 2,
        "high": 3
    }
    #contains security levels of objects and objects themselves
    objSecurityMap={}
    #contains security levels of subjects and subjects themselves
    subSecurityMap={}

    #this function makes sure that the subject is authorized to either read or write to an object by converting levels to integers
    def accessControl(self, operation, subject, objct, value=0):
        if operation == 'r':
            if self.levels[self.subSecurityMap[subject].lower()] >= self.levels[self.objSecurityMap[objct].lower()]:
                print "Access Granted :", subject.getName(), "reads", objct.getName()
                for s in self.subSecurityMap:
                    if s.getName()== subject.getName():
                        s.setValue(objct.getValue())
            else:
                print "Access Denied : read", subject.getName(), objct.getName()

        elif operation == 'w':
            if self.levels[self.subSecurityMap[subject].lower()] <= self.levels[self.objSecurityMap[objct].lower()]:
                print "Access Granted :", subject.getName(), "writes value", value, "to", objct.getName()
                for o in self.objSecurityMap:
                    if o.getName()== objct.getName():
                        o.setValue(value)
            else:
                print "Access Denied : write", subject.getName(), objct.getName(), value

    #this functions adds subject to the map initialized in the begining of this class
    def addSubject(self, name, security):
        sub = Subject(name)
        self.subSecurityMap[sub] = security
    #this function add objects when called
    def addObject(self, name, security):
        obj = Object(name)
        self.objSecurityMap[obj] = security
    
    #this function ensures that the subjects and objects passed in to perform a read exist in database 
    #then passes information to access control to ensure the right security levels
    def executeRead(self, subject, objct):
        #initializes obj and sub to None to check if user enters wrong names
        sub = None
        obj = None 
        #checks security map for the name of the entered subject so it can be passed to accesscontrol
        for s in self.subSecurityMap:
            if s.getName() == subject:
                sub = s
        #checks security map for the name of the entered object so it can be passed to accesscontrol
        for o in self.objSecurityMap:
            if o.getName() == objct:
                obj = o
        #checks if the subject and object entered exist, if they do they are passed to accesscontrol
        if sub is None or obj is None:
            print "Bad Instruction : read", subject, objct 
        else:
            #passed into access control to make sure they have correct security levels
            self.accessControl('r', sub, obj)

    #this function ensures that the subjects and objects passed in to perform a write exist in database 
    #then passes information to access control to ensure the right security levels
    def executeWrite(self, subject, objct, value):
        #initializes obj and sub to None to check if user enters wrong names
        sub = None
        obj = None 
        #checks security map for the name of the entered subject so it can be passed to accesscontrol
        for s in self.subSecurityMap:
            if s.getName() == subject:
                sub = s
        #checks security map for the name of the entered object so it can be passed to accesscontrol
        for o in self.objSecurityMap:
            if o.getName() == objct:
                obj = o
        #checks if the subject and object entered exist, if they do they are passed to accesscontrol
        if sub is None or obj is None or not value.isdigit():
            print "Bad Instruction : write", subject, objct, value
        else:
            #passed into access control to make sure they have correct security levels
            self.accessControl('w', sub, obj, value)

        
    
    #prints status of objects and subjects in formatted manner
    def printState(self):
        
        print ("{:<20} {:<20} {:<20}".format('Subject','Level','Value'))
        for sub in self.subSecurityMap:
           print ("{:<20} {:<20} {:<20}".format(sub.getName(), self.subSecurityMap[sub] , sub.getValue())) 
    
        print 

        print ("{:<20} {:<20} {:<20}".format('Object','Level','Value'))
        for obj in self.objSecurityMap:
            print ("{:<20} {:<20} {:<20}".format(obj.getName(), self.objSecurityMap[obj] , obj.getValue())) 
        
        



#opens file that is passed in throught comman line argument
with open(sys.argv[1], 'r') as inputFile:
    #creates reference monitor instance
    refMon=RefMon()

    #reads in input file, line by line
    for line in inputFile:
        #input value from user and splitted for parsing purposes
        line = line.strip()
        lineSet = line.strip().split()

        #adds subject to  reference monitor map
        if lineSet[0].lower() == "addsub" and len(lineSet)==3 and lineSet[2].lower() in refMon.levels:
            refMon.addSubject(lineSet[1], lineSet[2].upper())
            print "Subject Added :",line
        
        #adds object to  reference monitor map
        elif lineSet[0].lower() == "addobj" and len(lineSet)==3 and lineSet[2].lower() in refMon.levels:
            refMon.addObject(lineSet[1], lineSet[2].upper())
            print "Object Added :", line
        
        #prints state
        elif lineSet[0].lower() == "status" and len(lineSet)==1:
            print "\nCurrent State"
            refMon.printState()
            print 

        # performs read operation by invoking refmon's read function
        elif lineSet[0].lower() == "read" and len(lineSet)==3:
            refMon.executeRead(lineSet[1], lineSet[2])
        
        # performs write operation by invoking refmon's write function
        elif lineSet[0].lower() == "write" and len(lineSet)==4:
            refMon.executeWrite(lineSet[1], lineSet[2], lineSet[3])
        #if something is syntactically incorrect then its bad instruction
        else:
            print "Bad Instruction :", line

    #final state
    print "\nFinal State"
    refMon.printState()
    print 