#   Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
  
#   Licensed under the Apache License, Version 2.0 (the "License").
#   You may not use this file except in compliance with the License.
#   A copy of the License is located at
  
#       http://www.apache.org/licenses/LICENSE-2.0
  
#   or in the "license" file accompanying this file. This file is distributed 
#   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either 
#   express or implied. See the License for the specific language governing 
#   permissions and limitations under the License.

import boto3
import json
from botocore.exceptions import ClientError
import re
import logging
import logging.config
import csv
import sys
import os
import argparse
import time
from datetime import datetime
from progress.bar import ChargingBar, Bar
from pyfiglet import Figlet
from colorama import init,Fore, Back, Style
from terminaltables import SingleTable
from os.path import expanduser
from os import path
from iamctl.harvester import Harvester
from iamctl.differ import Differ
from pkg_resources import get_distribution, DistributionNotFound



def fix_me_a_directory(output):
    if output is None:
        output_directory = expanduser("~") + '/aws-idt/output' + time.strftime("/%Y/%m/%d/%H/%M/%S")
        if not os.path.exists(output_directory):
            os.makedirs(output_directory)
        return output_directory
    else:
        return output

def check_if_init():
    return os.path.isfile('iam.json') and os.path.isfile('equivalency_list.json')

def harvest(profile_name,account_name,output):
    if not check_if_init():
        print(Fore.YELLOW + 'Please initialize using "iamctl init"')
    else:
        output_directory = fix_me_a_directory(output)
        harvest = Harvester(profile_name, account_name, output_directory)
        #This will harvest all the iam roles from account-1 and write it to an extract file under output/ directory
        harvest.harvest_iam_roles_from_account()


def diff(profile_name_1, account_name_1, profile_name_2, account_name_2, output):
    if not check_if_init():
        print(Fore.YELLOW + 'Please initialize using "iamctl init"')
    else:
        output_directory = fix_me_a_directory(output)
        skip_harvest = False

        if  (os.path.isfile(f'{output_directory}/{account_name_1}_{profile_name_1}_iam_tuples.csv') and
             os.path.isfile(f'{output_directory}/{account_name_2}_{profile_name_2}_iam_tuples.csv')):
            file1 = f'{output_directory}/{account_name_1}_{profile_name_1}_iam_tuples.csv'
            file2 = f'{output_directory}/{account_name_2}_{profile_name_2}_iam_tuples.csv'
            while skip_harvest not in ('Y','N'):
                skip_harvest = input("Harvest files appear to exist, skip harvest?(Y/N)").upper()

        if skip_harvest != 'Y':
            harvest1 = Harvester(profile_name_1, account_name_1, output_directory)
            harvest2 = Harvester(profile_name_2, account_name_2, output_directory)
            #This will harvest all the iam roles from account-1 and write it to an extract file under output/ directory
            harvest1.harvest_iam_roles_from_account()
            #This will harvest all the iam roles from account-2 and write it to an extract file under output/ directory
            harvest2.harvest_iam_roles_from_account()

        #instantiating Differ object with extract file name from each of the harvest objects for both accounts.
        differ = Differ(file1, file2, account_name_1, account_name_2, output_directory)

        #This will generate the diff files comparing both accounts for IAM roles and prints the summary report to console
        differ.generate_diff_and_summary()

def init():
    print(Fore.BLUE + 'Initializing')
    print(Fore.BLUE + 'Downloading IAM file from awspolicygen S3 Bucket: iam.json')

    #create the iam.json file
    s3 = boto3.client('s3')
    
    response = s3.get_object(Bucket="awspolicygen", Key="js/policies.js")
    stream = response['Body']
    contents = stream.read().decode('utf-8')
    with open("iam.json", "w") as text_file:
        text_file.write(contents[23:])
    print(Fore.BLUE + 'Creating sample equivalency list file: equivalency_list.json')
    print(Style.RESET_ALL)

    #create the equivalency file
    data = {}
    data['accountid'] = ["123456789012","234567890123"]
    data['accountprefix1'] = ["apples-production","oranges-production","apples-development","oranges-development"]
    with open('equivalency_list.json', 'w') as outfile:
        json.dump(data, outfile)
    print(Fore.GREEN + u'\N{check mark} Done with Initialization.')
    print('-> Edit the Equivalency List file to ignore known variations, prefixes while running diff.')
    print('-> Run harvest or diff next.')
    print(Style.RESET_ALL)

def listprofiles():
    print(boto3.Session().available_profiles)

def main():
    __version__ = "0.0.1"
    try:
        __version__ = get_distribution("iamctl").version
    except DistributionNotFound:
        # package is not installed
        print("Hey distro not found!")
        pass
    
    log_file_path = path.join(path.dirname(path.abspath(__file__)), 'conf/logging.conf')
    logging.config.fileConfig(log_file_path)    

    # create self.logger, TBD change this to get logging conf based on class name
    logger = logging.getLogger(__name__)

    f = Figlet(font='bulbhead')
    print(Fore.BLUE + f.renderText('IAMctl'))
    print(Style.RESET_ALL)
    parser = argparse.ArgumentParser(description='IAMCTL is a tool built to make it easy to export, compare and analyze AWS IAM Roles, policies across accounts. Helpful for Auditing, Archiving. See below for more use-case specific commands and their requirements. Uses AWS Boto3 SDK and AWS CLI profiles')
    parser.add_argument('--version', '-V', '-v', action='version', version="%(prog)s " + __version__)
    subparsers = parser.add_subparsers(dest='subparser')

    init_parser = subparsers.add_parser('init',help='Downloads the IAM service specific actions, arn format and conditions to a file named iam.json in the current folder. Also creates a sample file named equivalency_list.json which could be used to ignore known string patterns in the IAM role names to be ignored to reduce false positives while running the diff command later')

    init_parser = subparsers.add_parser('listprofiles',help='Lists all CLI profiles available')


    harvest_parser = subparsers.add_parser('harvest', help='Downloads the IAM Roles, policies expands glob patterns, matches resources to service actions and writes the output as csv to default <user_home>/aws-idt directory with a time based folder structure')
    harvest_parser.add_argument('profile_name', help='AWS CLI Profile Name for Account-1')
    harvest_parser.add_argument('account_name', help='Account-1 Tag [Without any Spaces]')
    harvest_parser.add_argument('--output',dest ='output', help='Output directory location where files will be written to')

    diff_parser = subparsers.add_parser('diff', help='Compares the two accounts supplied as input for differences in IAM roles, policies by first harvesting from both accounts and then applying the equivalency list string patterns to ignore known false positive triggers. Write several summary level and granular observations to files to the default <user_home>/aws-idt directory with a time based folder structure ')
    diff_parser.add_argument('profile_name_1', help='AWS CLI Profile Name for Account-1')
    diff_parser.add_argument('account_name_1', help='Account-1 Tag [Without any Spaces]')
    diff_parser.add_argument('profile_name_2', help='AWS CLI Profile Name for Account-2')
    diff_parser.add_argument('account_name_2', help='Account-2 Tag [Without any Spaces]')
    diff_parser.add_argument('--output',dest ='output', help='Output directory location where files will be written to')

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    else:
        kwargs = vars(parser.parse_args())
        globals()[kwargs.pop('subparser')](**kwargs)



         



