Interp
====
<div id="sectmenu"></div>
Interps encapsulate the run-time state in Jsi.

Options
-------
Interp take numerous [options](Reference.md#new InterpOptions)
set-able via the command-line:

    jsish --T error foo.jsi

or programatically:

    "use strict,error";    
    var i = new Interp({name:'sub'});

Some options may only be set at interpreter creation time.

    Interp.conf();                              // Dump all options.
    Interp.conf('strict');                      // Get option.
    Interp.conf({strict:false, maxDepth:99});   // Set several options.

Various interp options can be set from the command-line:

    jsish --I isSafe
    jsish --I traceCall:cmds tests/while2.jsi
    jsish --T Debug

While other sensitive options can not be modified when in safe mode:

    jsish --I isSafe -e "Interp.conf({maxIncDepth:9999})"

==>

    error: Error isSafe disallows updating option: "maxIncDepth"    (at or near "maxIncDepth")


Subinterp
----
Sub-interps provides a self-contained, possibly restricted scripting environment:

    var i = new Interp();
    i.source('myfile.jsi');
    i.eval('myfunc();');
    i.call('myfunc', [1,2,3]);
    delete i;

[Interp](Reference.md#Interp) provides numerous methods and options.


Alias
----

**Inter.alias()** works much the same way as **bind()**:

    function foo(a,b) {
      puts('FOO: A='+a+' B='+b);
    }
    
    Interp.alias('bar', foo, [1]);
    bar(2);
    
    var bar2 = foo.bind(null,1);
    bar2(2);

==>

    FOO: A=1 B=2
    FOO: A=1 B=2

Sub-interpreters use **alias** to relay calls to the parent:

    function Super(arg1,arg2,arg3) {
       return ['SUPER',arg1,arg2,arg3];
    }
    
    ;' Define/Invoke Aliases';
    var i = new Interp();
    ;i.alias('foo', Super, []);
    ;i.alias('bar', Super, [i, 'bar']);
    
    ;i.eval('foo(1,2,3)');
    ;i.eval('bar(99)');

See test [alias2.jsi](/file/tests/alias2.jsi) for more examples and output.

Safe-Mode
----
Sub-interps created with the isSafe option
are restricted from using potentially dangerous facilties such as **exec** and the file system:

    new Interp({isSafe:true, scriptStr:"exec('ls');"}); 
    
==>

    error: no exec in safe mode    (at or near "ls")


Additional options may be used to influence or relax these limitations:

* **safeReadDirs**/**safeWriteDirs** : list of directories/files allowing write.
* **safeExecDirs** : list of directories allowing execute.
* **safeMode** : refined control for when executing a main script in safe mode.

Here is one example:

    var i = new Interp({isSafe:true, safeWriteDirs:['/tmp'], , safeReadDirs:['/tmp']});


### Command-Line
Safe execution of scripts can be invoked using **-s**:

    jsish -s tests/while.js a b c
    jsish -s tests/file.js a b c;  // Kicks a file access error.
    jsish -s                       // Interactive mode

### Lockdown
Lockdown mode ( enabled with **--L**) sets up safe mode
with read/write dirs, and *safeMode*=**lockdown**.

    jsish --L /tmp mywrite.jsi
    jsish --L my.db dbapp.jsi

* The main goal of lockdown is to disallow file-creation. This means the target must already exist.
* Lockdown disables various commands such as **File.write**.
* A common use for **lockdown** mode is limiting **I/O** only to existing databases files (ie. Sqlite).

Config-File
----
Interp options can load from a [JSON](./Builtins.md#JSON) file using **--C**:

    echo '{isSafe:true,safeMode:"lockdown",safeWriteDirs:["/tmp"]}' > jsish.conf
    jsish --C jsish.conf myapp.jsi

A system-wide config file, **/etc/jsish.conf** will load (if present) and over-riding all previous settings.
Thus copying the above jsish.conf into **/etc** will locked-down Jsi system wide.


Events
------
Various Jsi commands and extensions (eg. [websockets](Builtins.md#websocket)) implement asynchronous
features employing [events](Builtins.md#event).  Javascript events are created with *setTimeout*/*setInterval*,
scheduled with **update()**.

    var i = new Interp();
    i.eval("doWork();", true);
    //...
    update();


Threads
--------------
If a sub-interp is threaded, it must be given either *scriptFile* or *scriptStr*:

    var interp1 = new Interp({subthread:true, scriptFile:'mythrd.js'});

Function-calls between threaded interps use **call** and **alias**, as in this
[example](/file/js-demos/thread.jsi):

    #!/usr/bin/env jsish
    "use strict";
    // Threaded interp with call, eval and alias.

    function MySuper(x,y) { puts('MySuper', x,y); }
    
    var cnt=0, i = new Interp({subthread:true, name:'Subby', scriptStr: "
        function Sub(s) { puts('Sub: ',s); Super(s); return {x:8, y:s.AA}; };
    
        puts('Child starting:', Info.interp().name);
    
        while (1) {
            update(1000);
            Super(1);
            puts('Child-loop');
        };
    "});
    
    i.alias('Super', MySuper, [1]);
    
    var obj = {AA:0,BB:2};
    i.call('Sub',[obj]);
    while (cnt<10) {
      obj.AA++;
      update(100);
      puts("Main-loop");
      if (((cnt++)%3)==0)
          i.eval("puts('A sub-interp eval');");
      puts('RET=', i.call('Sub',[obj], true));
    }

Also see [threadn.jsi](/file/js-demos/threadn.jsi).

JSON
----
Data shared between interps are restricted to *string*-only.
Other forms of data internally gets converted to and from [JSON](Builtins.md#json).
All this happens automatically meaning there are no concerns,
other than data translation and performance issues related to using JSON.


