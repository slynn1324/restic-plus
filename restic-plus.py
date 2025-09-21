#!/usr/bin/env python3

import argparse
import subprocess
import configparser
import re
import json
import traceback
import os
import sys
import signal

RESTIC_GLOBAL_ARGS = [
	"cacert",
	"cache-dir",
	"cleanup-cache",
	"compression",
	"insecure-tls",
	"json",
	"key-hint",
	"limit-download",
	"limit-upload",
	"no-cache",
	"no-lock",
	"option"
	"pack-size",
	"password-command",
	"password-file",
	"quiet",
	"repo",
	"repository-file",
	"retry-lock",
	"tls-client-cert",
	"verbose"
]

# just exit without printing stacktrace on sigint (ctrl+c)
def sigint_handler(signal, frame):
	sys.exit(0)
signal.signal(signal.SIGINT, sigint_handler)

# custom exception class so we can identify our own exceptions
class RPException(Exception):
	pass


config_parser = configparser.ConfigParser(empty_lines_in_values=False, allow_no_value=True)
config_parser.SECTCRE = re.compile(r"\[ *(?P<header>[^]]+?) *\]")
config_parser.optionxform = lambda option: option
config_parser.read(os.path.join(os.path.expanduser("~/.config/restic-plus/restic-plus.conf")))

def create_epilog():

	rval = "-"*76 + "\n"
	rval += "Configuration File: " + os.path.join(os.path.expanduser("~/.config/restic-plus/restic-plus.conf")) + "\n\n"
	rval += "Jobs:\n" 
	for k in config_parser:
		if re.match(".+@.+", k):
			rval += "    " + k + "\n"
	rval += "\n"

	rval += "Groups:\n"
	for k in config_parser:
		if re.match("group[.].+", k):
			rval += "    " + k + "\n"
	rval += "\n"
	
	return rval


arg_parser = argparse.ArgumentParser(description="Configured wrapper for restic backup.", epilog=create_epilog(), formatter_class=argparse.RawDescriptionHelpFormatter)
arg_parser.add_argument("job")
arg_parser.add_argument("action")

(args, other_args) = arg_parser.parse_known_args()

def is_verbose():
	return os.environ.get("RESTIC_PLUS_VERBOSE") == "1"

def bytes_to_human(num):
	for unit in ("B", "K", "M", "G"):
		if abs(num) < 1024.0:
			return f"{num:3.1f}{unit}"
		num /= 1024.0
	return f"{num:.1f}T"

def bytes_from_human(val):
	val = val.strip()
	if val.endswith("T"):
		return int(val[0:-1]) * 1024 * 1024 * 1024 * 1024
	if val.endswith("G"):
		return int(val[0:-1]) * 1024 * 1024 * 1024
	if val.endswith("M"):
		return int(val[0:-1]) * 1024 * 1024
	if val.endswith("K"):
		return int(val[0:-1]) * 1024
	if val.endswith("B"):
		return int(val[0:-1])
	raise RPException("unknown byte pattern, must end with T, G, M, K, or B")

def get_dict_for_config_section(section):
	if section in config_parser:
		return dict(config_parser[section])
	return {}

def get_config_for_job(job):
	job_match = re.match('^([a-zA-Z0-9-]+)@([a-zA-Z0-9-]+)$', job)
	if not job_match:
		raise RPException("invalid job name '{}'".format(job))

	location = job_match[1]
	target = job_match[2]


	rval = { "name": job, "env":{}, "flags":{}, "paths": [], "args":[], "max-size": None, "restic-binary": "restic" }
	job_section = config_parser[job]

	all_items = {}
	all_items.update(get_dict_for_config_section("global"))
	all_items.update(get_dict_for_config_section("global.{}".format(args.action)))
	all_items.update(get_dict_for_config_section("{}@".format(location)))
	all_items.update(get_dict_for_config_section("{}@.{}".format(location, args.action)))
	all_items.update(get_dict_for_config_section("@{}".format(target)))
	all_items.update(get_dict_for_config_section("@{}.{}".format(target, args.action)))
	all_items.update(get_dict_for_config_section(job))
	all_items.update(get_dict_for_config_section("{}.{}".format(job, args.action)))

	# recreate all_items, making all values arrays split by "\n" and removing blank lines
	# all_items = { k : ([ i for i in v.split("\n") if i ] if v else None) for k,v in all_items.items() }
	
	for (k,v) in all_items.items():
		if k.startswith("$"):
			rval['env'][k[1:]] = v
		elif k == "restic-binary":
			rval['restic-binary'] = v
		elif k == "max-size":
			rval['max-size'] = v
		elif k == "paths":
			rval['paths'] = [ i for i in v.split("\n") if i ] if v else None
		elif k == "args":
			rval['args'].extend([ i for i in v.split("\n") if i ]) # no blank lines
		else:
			rval['flags'][k] = [ i for i in v.split("\n") if i ] if v else None # no blank lines

	return rval

def get_config_for_group(group):
	rval = { "jobs": [] }
	group_section = config_parser["group." + group]
	if "jobs" in group_section:
		rval['jobs'] = [ i for i in group_section["jobs"].split("\n") if i ] # no blank lines
	return rval

def only_global_flags(job_config):
	rval = {}
	for (k,v) in job_config['args']:
		if k in RESTIC_GLOBAL_ARGS:
			rval[k] = v
	return rval

def format_flags(flags):
	rval = []
	for (k,v) in flags.items():
		if k.startswith("-"):
			rval.append(k)
		else:
			rval.append("--{}".format(k))
		if v:
			rval.extend(v)
	return rval

def get_repo_flag(flags):
	if "repo" in flags:
		return ["--repo", flags["repo"][0]]
	elif "--repo" in flags:
		return ["--repo", flags["--repo"][0]]
	elif "-r" in flags:
		return ["--repo", flags["-r"][0]]
	else:
		raise RPException("unable to get repo from args")

def get_repo_size(job_config, run_env):
	cmd = [job_config['restic-binary'], "stats", "--json", "--mode", "raw-data"]
	cmd.extend( format_flags( only_global_flags(job_config) ) )
	cmd.extend( get_repo_flag(job_config["flags"]) )

	if is_verbose():
		print("get_repo_size cmd: {}".format(cmd))
	
	print("getting existing repo size...")

	result = subprocess.run(cmd, env=run_env, check=True, capture_output=True)
	out = result.stdout.splitlines()[-1]

	if is_verbose():
		print(out)

	repo_size = json.loads(out)['total_size']
	print("repo size is {}".format(bytes_to_human(repo_size)))

	return repo_size

def get_bytes_to_add(backup_cmd, run_env):
	cmd = backup_cmd.copy()
	if "--verbose" in cmd:
		cmd.remove("--verbose") 
	if "-v" in cmd:
		cmd.remove("-v")
	if "--dry-run" not in cmd and "-n" not in cmd:
		cmd.append("--dry-run")
	cmd.append("--quiet")
	cmd.append("--json")

	if is_verbose():
		print("get_bytes_to_add_cmd: {}".format(cmd))

	print("getting bytes to add...")

	result = subprocess.run(cmd, env=run_env, check=True, capture_output=True)
	out = result.stdout.splitlines()[-1]

	if is_verbose():
		print(out)

	bytes_to_add = json.loads(out)['data_added']
	print("bytes to add is {}".format(bytes_to_human(bytes_to_add)))
	
	return bytes_to_add

def run_job(job):
	job_config = get_config_for_job(job)

	run_env = os.environ.copy()
	run_env.update(job_config['env'])

	cmd = [job_config['restic-binary'], args.action]
	cmd.extend( format_flags(job_config['flags'] ) )
	cmd.extend( job_config['args'] )
	cmd.extend( other_args )

	if args.action == "backup":
		cmd.extend( job_config['paths'] )

	
	if job_config['max-size'] and args.action == "backup":
		repo_size = get_repo_size(job_config, run_env)
		bytes_to_add = get_bytes_to_add(cmd, run_env)
		max_size_bytes = bytes_from_human(job_config['max-size'])
		new_repo_size = repo_size + bytes_to_add

		if new_repo_size > max_size_bytes:
			raise RPException("job {} will be {} exceeding max size of {}".format(job_config['name'], bytes_to_human(new_repo_size), job_config['max-size']))
		else:
			print("job {} will be {} under max size of {}".format(job_config['name'], bytes_to_human(new_repo_size), job_config['max-size']))

	
	if is_verbose():
		print("restic cmd: {}".format(cmd))
	subprocess.run(cmd, env=run_env, check=True)




def main():

	if args.job.find("@") > -1:
		# it's a job
		try:
			run_job(args.job)
		except Exception as e:
			print(e, file=sys.stderr)

	else:
		# its a group
		group_config = get_config_for_group(args.job)

		if not args.action in ["backup", "snapshots", "check"]:
			print("action '{}' is not allowed on a group.  Supported actions: backup, check, snapshots".format(args.action))
			sys.exit(1)

		for job in group_config['jobs']:
			try:
				print("Running job: {}".format(job))
				run_job(job)
				print("\n")
			except Exception as e:
				print("error running job {}: {}\n\n".format(job, e), file=sys.stderr)


main()
