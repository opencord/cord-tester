import os,sys
##add the python path to lookup the utils
working_dir = os.path.dirname(os.path.realpath(sys.argv[-1]))
utils_dir = os.path.join(working_dir, '../utils')
fsm_dir = os.path.join(working_dir, '../fsm')
cli_dir = os.path.join(working_dir, '../cli')
subscriber_dir = os.path.join(working_dir, '../subscriber')
__path__.append(utils_dir)
__path__.append(fsm_dir)
__path__.append(cli_dir)
__path__.append(subscriber_dir)
