# CodeKnife

*A static analysis tool for iOS applications that have been decrypted.*

## Environment Requirement

* Python with version 3.6 and above
* Flask
* Capstone
* MongoDB
* pip3 install graphviz
* pip3 install tqdm

## Functions

Before running this system, you should start `MongoDB` in default port(27017):

```sh
$ mongod -dbpath=<db_pat>
```

And then, you can enter the directory of *CodeKnife/view*, and type the follow instruction, you can run this system:

```sh
$ python3 home.py
```

You can access this system in *http://127.0.0.1:5000*.

### Basic Analysis

You can choose any decrypted **.ipa** or **.app** file to upload, and you can see the basic analysis in default.
In this function, you can see the basic info of this application, about MD5 of executable file, permissions and some developed files in app bundle.

### Binary Analysis

In binary analysis, you can see all segments in iOS application.

#### Class

If you choose Class tab in the left, you can see all the Class in this application, and when you press any class, you can see the detail information about this class, about properties and methods. You can search class name if there are too many classes.

#### Method

In the Method tab, you can see all methods of current application, when you press any method, you can see the CFG and DFG of this method, also, in the top tool bar, you can switch into code mode to see the detail instructions of this method. You can filter all the methods by class name when there are too many methods.

#### Checkers

Because the attack surfaces will change, to improve extensive of this system, there are checker's scripts in the Checkers tab.

In the checkers, you can see all the scripts which can be executed to check this application's method. For example, if you choose **background_check**, you can see the script as follows:

```python
background_methods = {
    '*': ['applicationWillResignActive:', 'applicationDidEnterBackground:']
}

background_behaviours = callee.find_api(background_methods)
for _class in background_behaviours:
    ck_log(_class)
```

And if you click the green button run in the top right, you can see the output in the bottom window, which can output all methods called in the *applicationWillResignActive:* and *applicationDidEnterBackground:* methods of any class (specified by *\** in the code).

Generally, you can write scripts by your self to do checking operation. To find which methods call current method, you can use *caller.find({method-pair})* and to find which methods are called by current method, you can use *callee.find({class-method})*, you can see the examples in the inner checkers.

## Demos

In the directory *CodeKnife/Demos*, there are some demo applications, you can upload these applications to find this system's functions.
