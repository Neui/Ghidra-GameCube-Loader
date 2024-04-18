# Ghidra GameCube Loader
A  Nintendo GameCube binary loader for [Ghidra](https://github.com/NationalSecurityAgency/ghidra).

Includes optional symbol map importing, automatic namespace creation, and demangling support.

## Supported Formats
* DOL Executables (.dol)
* Relocatable Modules (.rel)
* Apploaders
* RAM Dumps

## Building
- Ensure you have ``JAVA_HOME`` set to the path of your JDK 17 installation.
- Set ``GHIDRA_INSTALL_DIR`` to your Ghidra install directory. This can be done in one of the following ways:
    - **Windows**: Running ``set GHIDRA_INSTALL_DIR=<Absolute path to Ghidra without quotations>``
    - **macos/Linux**: Running ``export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra>``
    - Using ``-PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra>`` when running ``./gradlew``
    - Adding ``GHIDRA_INSTALL_DIR`` to your Windows environment variables.
- Run ``./gradlew``
- You'll find the output zip file inside `/dist`

## Installation
- Copy the zip file to ``<Ghidra install directory>/Extensions/Ghidra``.
- Start Ghidra and use the "Install Extensions" dialog to finish the installation. (``File -> Install Extensions...``).

## Developing with Eclipse
1. Make sure to install the official *GhidraDev* plugin.
2. Add the Repository folder to Eclipse.
    1. Clone the project anywhere, then in Eclipse: *File* → *Open Projects from File System...*
    2. Under `Import source:`, input the source directory.
    3. Make sure the checkbox *Detect and configure project natures* is set (which is the default)
    4. Click *Finish*.
3. The repository should appear in *Project Explorer* as a project. Right click on it and there should be *Gradle* → *Refresh Gradle Project*.
    **Use this when you modified build files, and follow the steps after until including linking with Ghidra!**
    - You may need to configure the Ghidra Install directory for Gradle:
       1. Right click on the project → *Properties* → *Gradle* (left) → chekc *Override workspace settings* →under *Advanged Options* - *Program Arguments* click on *Add*.
       2. Double click on the newly-appeared *arg* set type `-PGHIDRA_INSTALL_DIR=/path/to/your/ghidra_11.0.1_PUBLIC/`. Change the path to your installation of course.
       3. Press enter. The window will close, but don't worry, it'll be saved.
    **Use this when you modified build files, and follow the steps after until including linking with Ghidra.**.
4. Gradle added Ghidra as a dependency except Ghidra documentation and source code browsing won't be available, so remove those to let the configuration by *Link Ghidra...* take priority later.
    1. Right click on project and select *Properties*
    2. On the left, select *Java Build Path*
    3. On the right, select *Libraries* tab.
    4. Expand *Classpath*, select *Project and External Dependencies* and then click on *Remove* on the very right (or press the DEL key on your keyboard).
    5. *Apply and Close* at the bottom right.  
5. Now we can "link with Ghidra".
    1. Right click on the project → *GhidraDev* → *Link Ghidra...* 
    2. Follow the assistant. You don't need Python support.
6. Unfortunately since we deleted the dependencies, we need to re-add them (JUnit4).
    1. Open *Problems* tab, expand *Errors*, right click on an error about testing and click on *Quick Fix*.
    2.  Under *Select a fix:*, click on *Add JUint 4 library to the build path*, then on *Finish*.  
7. Ghidra won't find some data files (like the language files).
    1. Click on the down arrow next to the bug icon in the top tool bar (*Debug As...*) and select *Debug Configurations...*
    2. On the left, select *Ghidra* and click on the white paper symbol on the mini tool bar (`New launch configuration*)
    3. Set a name and set the Project.
    4. Switch to tab *Classpath* and scroll down to *User Entries*.
    5. Select it, and click on *Advanced...* on the right, select *Add Folders* then *OK*, and select the `bin` folder inside the project directory.
    6. Click on *Apply* then *Close* (or *Debug* to start) on the bottom right.    
8. Now you can actually run Ghidra: Click on the bug icon in the tool bar to launch Ghidra with this extension.
   Don't forget to uninstall the extension if you had it installed before, otherwise there will be conflicts.

	