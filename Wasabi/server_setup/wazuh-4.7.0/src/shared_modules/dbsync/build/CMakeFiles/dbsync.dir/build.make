# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.18

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/build

# Include any dependencies generated for this target.
include CMakeFiles/dbsync.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/dbsync.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/dbsync.dir/flags.make

CMakeFiles/dbsync.dir/src/dbsync.cpp.o: CMakeFiles/dbsync.dir/flags.make
CMakeFiles/dbsync.dir/src/dbsync.cpp.o: ../src/dbsync.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/dbsync.dir/src/dbsync.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/dbsync.dir/src/dbsync.cpp.o -c /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/src/dbsync.cpp

CMakeFiles/dbsync.dir/src/dbsync.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/dbsync.dir/src/dbsync.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/src/dbsync.cpp > CMakeFiles/dbsync.dir/src/dbsync.cpp.i

CMakeFiles/dbsync.dir/src/dbsync.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/dbsync.dir/src/dbsync.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/src/dbsync.cpp -o CMakeFiles/dbsync.dir/src/dbsync.cpp.s

CMakeFiles/dbsync.dir/src/dbsyncPipelineFactory.cpp.o: CMakeFiles/dbsync.dir/flags.make
CMakeFiles/dbsync.dir/src/dbsyncPipelineFactory.cpp.o: ../src/dbsyncPipelineFactory.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/dbsync.dir/src/dbsyncPipelineFactory.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/dbsync.dir/src/dbsyncPipelineFactory.cpp.o -c /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/src/dbsyncPipelineFactory.cpp

CMakeFiles/dbsync.dir/src/dbsyncPipelineFactory.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/dbsync.dir/src/dbsyncPipelineFactory.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/src/dbsyncPipelineFactory.cpp > CMakeFiles/dbsync.dir/src/dbsyncPipelineFactory.cpp.i

CMakeFiles/dbsync.dir/src/dbsyncPipelineFactory.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/dbsync.dir/src/dbsyncPipelineFactory.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/src/dbsyncPipelineFactory.cpp -o CMakeFiles/dbsync.dir/src/dbsyncPipelineFactory.cpp.s

CMakeFiles/dbsync.dir/src/dbsync_implementation.cpp.o: CMakeFiles/dbsync.dir/flags.make
CMakeFiles/dbsync.dir/src/dbsync_implementation.cpp.o: ../src/dbsync_implementation.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/dbsync.dir/src/dbsync_implementation.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/dbsync.dir/src/dbsync_implementation.cpp.o -c /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/src/dbsync_implementation.cpp

CMakeFiles/dbsync.dir/src/dbsync_implementation.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/dbsync.dir/src/dbsync_implementation.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/src/dbsync_implementation.cpp > CMakeFiles/dbsync.dir/src/dbsync_implementation.cpp.i

CMakeFiles/dbsync.dir/src/dbsync_implementation.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/dbsync.dir/src/dbsync_implementation.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/src/dbsync_implementation.cpp -o CMakeFiles/dbsync.dir/src/dbsync_implementation.cpp.s

CMakeFiles/dbsync.dir/src/sqlite/sqlite_dbengine.cpp.o: CMakeFiles/dbsync.dir/flags.make
CMakeFiles/dbsync.dir/src/sqlite/sqlite_dbengine.cpp.o: ../src/sqlite/sqlite_dbengine.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/dbsync.dir/src/sqlite/sqlite_dbengine.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/dbsync.dir/src/sqlite/sqlite_dbengine.cpp.o -c /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/src/sqlite/sqlite_dbengine.cpp

CMakeFiles/dbsync.dir/src/sqlite/sqlite_dbengine.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/dbsync.dir/src/sqlite/sqlite_dbengine.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/src/sqlite/sqlite_dbengine.cpp > CMakeFiles/dbsync.dir/src/sqlite/sqlite_dbengine.cpp.i

CMakeFiles/dbsync.dir/src/sqlite/sqlite_dbengine.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/dbsync.dir/src/sqlite/sqlite_dbengine.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/src/sqlite/sqlite_dbengine.cpp -o CMakeFiles/dbsync.dir/src/sqlite/sqlite_dbengine.cpp.s

CMakeFiles/dbsync.dir/src/sqlite/sqlite_wrapper.cpp.o: CMakeFiles/dbsync.dir/flags.make
CMakeFiles/dbsync.dir/src/sqlite/sqlite_wrapper.cpp.o: ../src/sqlite/sqlite_wrapper.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/dbsync.dir/src/sqlite/sqlite_wrapper.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/dbsync.dir/src/sqlite/sqlite_wrapper.cpp.o -c /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/src/sqlite/sqlite_wrapper.cpp

CMakeFiles/dbsync.dir/src/sqlite/sqlite_wrapper.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/dbsync.dir/src/sqlite/sqlite_wrapper.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/src/sqlite/sqlite_wrapper.cpp > CMakeFiles/dbsync.dir/src/sqlite/sqlite_wrapper.cpp.i

CMakeFiles/dbsync.dir/src/sqlite/sqlite_wrapper.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/dbsync.dir/src/sqlite/sqlite_wrapper.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/src/sqlite/sqlite_wrapper.cpp -o CMakeFiles/dbsync.dir/src/sqlite/sqlite_wrapper.cpp.s

# Object files for target dbsync
dbsync_OBJECTS = \
"CMakeFiles/dbsync.dir/src/dbsync.cpp.o" \
"CMakeFiles/dbsync.dir/src/dbsyncPipelineFactory.cpp.o" \
"CMakeFiles/dbsync.dir/src/dbsync_implementation.cpp.o" \
"CMakeFiles/dbsync.dir/src/sqlite/sqlite_dbengine.cpp.o" \
"CMakeFiles/dbsync.dir/src/sqlite/sqlite_wrapper.cpp.o"

# External object files for target dbsync
dbsync_EXTERNAL_OBJECTS =

lib/libdbsync.so: CMakeFiles/dbsync.dir/src/dbsync.cpp.o
lib/libdbsync.so: CMakeFiles/dbsync.dir/src/dbsyncPipelineFactory.cpp.o
lib/libdbsync.so: CMakeFiles/dbsync.dir/src/dbsync_implementation.cpp.o
lib/libdbsync.so: CMakeFiles/dbsync.dir/src/sqlite/sqlite_dbengine.cpp.o
lib/libdbsync.so: CMakeFiles/dbsync.dir/src/sqlite/sqlite_wrapper.cpp.o
lib/libdbsync.so: CMakeFiles/dbsync.dir/build.make
lib/libdbsync.so: CMakeFiles/dbsync.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Linking CXX shared library lib/libdbsync.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/dbsync.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/dbsync.dir/build: lib/libdbsync.so

.PHONY : CMakeFiles/dbsync.dir/build

CMakeFiles/dbsync.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/dbsync.dir/cmake_clean.cmake
.PHONY : CMakeFiles/dbsync.dir/clean

CMakeFiles/dbsync.dir/depend:
	cd /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/build /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/build /root/BlueBox/Wasabi/server_setup/wazuh-4.7.0/src/shared_modules/dbsync/build/CMakeFiles/dbsync.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/dbsync.dir/depend

