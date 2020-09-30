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

class Differ:
    def __init__(self, extract_file_name_1, extract_file_name_2, account_1_tag, account_2_tag, output_directory):

        self.output_directory=output_directory
        self.logger = logging.getLogger(__name__)
        self.extract_file_name_1 = extract_file_name_1
        self.extract_file_name_2 = extract_file_name_2
        self.extract_file_handler_1 = None
        self.extract_file_handler_2 = None
        self.account_1_tag = account_1_tag
        self.account_2_tag = account_2_tag
        self.account_1_raw = None
        self.account_2_raw = None
        self.equivalency_list_dict = None
        self.account_1_to_account_2_csv_out = None
        self.account_2_to_account_1_csv_out = None
        self.read_equivalency_dict()
        self.read_extract_files()

    def read_equivalency_dict(self):
        with open('equivalency_list.json') as f:
            self.equivalency_list_dict = json.load(f)

    def read_extract_files(self):
        # Read the 2 extract files.
        with open(self.extract_file_name_1) as f:
            self.extract_file_handler_1 = f
            next(csv.reader(f))
            self.account_1_raw = [tuple(line) for line in csv.reader(f)]

        with open(self.extract_file_name_2) as f:
            self.extract_file_handler_2 = f
            next(csv.reader(f))
            self.account_2_raw = [tuple(line) for line in csv.reader(f)]

    # Get values after matching equivalency list
    def sanitize_value_with_equivalency(self, value):
        for key, valuelist in self.equivalency_list_dict.items():
            for eachvalue in valuelist:
                value = value.replace(eachvalue, key)
        return value

    # Get list after matching equivalency list.
    def get_sanitized_list_with_equivalency(self, tuples, tag):
        output_list = []
        bar = ChargingBar('Sanitizing IAM items from '+tag, max=len(tuples),suffix='%(index)d/%(max)d')
        for each_tuple in tuples:
            output_tuple = []
            for each_item in each_tuple:
                output_tuple.append(self.sanitize_value_with_equivalency(each_item))
            output_list.append(tuple(output_tuple))
            bar.next()
        bar.finish()
        return output_list

    def write_to_csv(self,tuples, header, filename):
        filehandler = open(self.output_directory+ "/" + filename, "wt", newline='')
        csv_out = csv.writer(filehandler)
        csv_out.writerow(header)
        for each_tuple in tuples:
            csv_out.writerow(each_tuple)
        filename = filehandler.name
        filehandler.close()
        return filename

    def generate_diff_and_summary(self):

        summary = []
        summary.append(['Metric', self.account_1_tag, self.account_2_tag])

        sanitized_account_1_list = self.get_sanitized_list_with_equivalency(self.account_1_raw, self.account_1_tag)
        sanitized_account_2_list = self.get_sanitized_list_with_equivalency(self.account_2_raw, self.account_2_tag)
        
        print(Style.BRIGHT)
        print(Fore.BLUE + "Summary report in text format:")
        print(Style.RESET_ALL)

        print("Number of items in %s: %d" %(self.account_1_tag, len(self.account_1_raw)))
        print("Number of items in %s: %d" %(self.account_2_tag, len(self.account_2_raw)))
        
        summary.append(['Harvested Items', len(self.account_1_raw), len(self.account_2_raw)])
        
        print("Number of items in %s after sanitizing: %d" % (self.account_1_tag, len(sanitized_account_1_list)))
        print("Number of items in %s after sanitizing: %d" % (self.account_2_tag, len(sanitized_account_2_list)))

        summary.append(['Sanitized Items', len(sanitized_account_1_list), len(sanitized_account_2_list)])

        account_1_roles = set([(item[0], item[1]) for item in sanitized_account_1_list])
        print("Number of roles in %s: %d" %(self.account_1_tag, len(account_1_roles)))
        headerrow =('rolename', 'path')
        filename = self.account_1_tag + "_roles.csv"
        self.write_to_csv(account_1_roles, headerrow, filename)

        account_1_service_linked_roles = set([(item[0],) for item in sanitized_account_1_list if (item[1].startswith('/aws-service-role/'))])
        print("Number of service linked roles in %s: %d" %(self.account_1_tag, len(account_1_service_linked_roles)))
        headerrow =('rolename',)
        filename = self.account_1_tag + "_service_linked_roles.csv"
        self.write_to_csv(account_1_service_linked_roles, headerrow, filename)

        account_1_non_service_linked_roles = set([(item[0],) for item in sanitized_account_1_list if not item[1].startswith('/aws-service-role/')])
        print("Number of Non-service linked roles in %s: %d" %(self.account_1_tag, len(account_1_non_service_linked_roles)))
        headerrow =('rolename',)
        filename = self.account_1_tag + "_non_service_linked_roles.csv"
        self.write_to_csv(account_1_non_service_linked_roles, headerrow, filename)

        account_2_roles = set([(item[0],item[1]) for item in sanitized_account_2_list])
        print("Number of roles in %s: %d" %(self.account_2_tag, len(account_2_roles)))
        headerrow =('rolename', 'path')
        filename = self.account_2_tag + "_roles.csv"
        self.write_to_csv(account_2_roles, headerrow, filename)    

        account_2_service_linked_roles = set([(item[0],) for item in sanitized_account_2_list if (item[1].startswith('/aws-service-role/'))])
        print("Number of service linked roles in %s: %d" %(self.account_2_tag, len(account_2_service_linked_roles)))
        headerrow =('rolename',)
        filename = self.account_2_tag + "_service_linked_roles.csv"
        self.write_to_csv(account_2_service_linked_roles, headerrow, filename)

        account_2_non_service_linked_roles = set([(item[0],) for item in sanitized_account_2_list if not item[1].startswith('/aws-service-role/')])
        print("Number of Non-service linked roles in %s: %d" %(self.account_2_tag, len(account_2_non_service_linked_roles)))
        headerrow =('rolename',)
        filename = self.account_2_tag + "_non_service_linked_roles.csv"
        self.write_to_csv(account_2_non_service_linked_roles, headerrow, filename)

        summary.append(['Roles',len(account_1_roles), len(account_2_roles)])
        summary.append(['Service Linked Roles', len(account_1_service_linked_roles), len(account_2_service_linked_roles)])
        summary.append(['Non-Service Linked Roles', len(account_1_non_service_linked_roles), len(account_2_non_service_linked_roles)])

        # Getting list of common roles between 2 accounts using bitwise operator.
        # If roles are common will return a 1.
        common_role_list = set(account_1_roles) & set(account_2_roles)
        print("Number of common roles: %d" %( len(common_role_list)))
        headerrow =('rolename', 'path')
        filename = "common_roles.csv"
        self.write_to_csv(common_role_list, headerrow, filename)

        common_service_linked_role_list = [(item[0],) for item in common_role_list if item[1].startswith('/aws-service-role/')]
        print("Number of common roles that are service linked: %d" %(len(common_service_linked_role_list)))
        headerrow =('rolename',)
        filename = "common_service_linked_roles.csv"
        self.write_to_csv(common_service_linked_role_list, headerrow, filename)

        common_non_service_linked_role_list = [(item[0],) for item in common_role_list if not item[1].startswith('/aws-service-role/')]
        print("Number of common roles that are Non-service linked: %d" %(len(common_non_service_linked_role_list)))
        headerrow =('rolename',)
        filename = "common_non_service_linked_roles.csv"
        self.write_to_csv(common_non_service_linked_role_list, headerrow, filename)

        summary.append(['Common Roles', len(common_role_list), len(common_role_list)])
        summary.append(['Common Service Linked Roles', len(common_service_linked_role_list), len(common_service_linked_role_list)])
        summary.append(['Common Non-Service Linked Roles', len(common_non_service_linked_role_list), len(common_non_service_linked_role_list)])

        # Get roles that are in first but not in second.
        account_1_diff_account_2 = set(account_1_roles) - set(account_2_roles) 


        #difference in items will not translate to roles, for e.g. you could have a role in account-a that has action item that is not in account-b
        account_1_diff_account_2_roles =  set([(item[0],item[1]) for item in account_1_diff_account_2])
        print("Number of roles from %s not in %s: %d" %(self.account_1_tag,self.account_2_tag, len(account_1_diff_account_2_roles)))
        headerrow =('rolename', 'path')
        filename = "roles_in_" + self.account_1_tag + "_but_not_in_" + self.account_2_tag + ".csv"
        self.write_to_csv(account_1_diff_account_2_roles, headerrow, filename)

        account_1_diff_account_2_service_linked_roles= [tup for tup in account_1_diff_account_2_roles if tup[1].startswith('/aws-service-role/')]
        print("Number of service linked roles from %s not in %s: %d" %(self.account_1_tag,self.account_2_tag, len(account_1_diff_account_2_service_linked_roles)))
        headerrow =('rolename', 'path')
        filename = "service_linked_roles_in_" + self.account_1_tag + "_but_not_in_" + self.account_2_tag+" .csv"
        self.write_to_csv(account_1_diff_account_2_service_linked_roles, headerrow, filename)

        account_1_diff_account_2_non_service_linked_roles= [tup for tup in account_1_diff_account_2_roles if not tup[1].startswith('/aws-service-role/')]
        print("Number of non-service linked roles from %s not in %s: %d" %(self.account_1_tag, self.account_2_tag, len(account_1_diff_account_2_non_service_linked_roles)))
        headerrow =('rolename', 'path')
        filename = "non_service_linked_roles_in_" + self.account_1_tag + "_but_not_in_" + self.account_2_tag + ".csv"
        self.write_to_csv(account_1_diff_account_2_non_service_linked_roles, headerrow, filename)

        # Get roles that are in second but not in first. 

        account_2_diff_account_1 = set(account_2_roles) - set(account_1_roles) 
        account_2_diff_account_1_roles =  list(set([(item[0],item[1]) for item in account_2_diff_account_1]))
        print("Number of roles from %s not in %s: %d" %(self.account_2_tag,self.account_1_tag, len(account_2_diff_account_1_roles)))
        headerrow =('rolename', 'path')
        filename = "roles_in_" + self.account_2_tag + "_but_not_in_" + self.account_2_tag + ".csv"
        self.write_to_csv(account_2_diff_account_1_roles, headerrow, filename)

        account_2_diff_account_1_service_linked_roles= [tup for tup in account_2_diff_account_1_roles if tup[1].startswith('/aws-service-role/')]
        print("Number of service linked roles from %s not in %s: %d" %(self.account_2_tag,self.account_1_tag, len(account_2_diff_account_1_service_linked_roles)))
        headerrow =('rolename', 'path')
        filename = "service_linked_roles_in_" + self.account_2_tag + "_but_not_in_" + self.account_1_tag + ".csv"
        self.write_to_csv(account_2_diff_account_1_service_linked_roles, headerrow, filename)


        account_2_diff_account_1_non_service_linked_roles= [tup for tup in account_2_diff_account_1_roles if not tup[1].startswith('/aws-service-role/')]
        print("Number of non-service linked roles from %s not in %s: %d" %(self.account_2_tag, self.account_1_tag, len(account_2_diff_account_1_non_service_linked_roles)))
        headerrow =('rolename', 'path')
        filename = "non_service_linked_roles_in_" + self.account_2_tag + "_but_not_in_" + self.account_1_tag + ".csv"
        self.write_to_csv(account_2_diff_account_1_non_service_linked_roles, headerrow, filename)

        summary.append(['Unique Roles', len(account_1_diff_account_2_roles), len(account_2_diff_account_1_roles)])
        summary.append(['Unique Service Linked Roles', len(account_1_diff_account_2_service_linked_roles), len(account_2_diff_account_1_service_linked_roles)])
        summary.append(['Unique Non-Service Linked Roles', len(account_1_diff_account_2_non_service_linked_roles), len(account_2_diff_account_1_non_service_linked_roles)])

        account_1_diff_items_account_2 = set(sanitized_account_1_list).difference(set(sanitized_account_2_list))
        account_2_diff_items_account_1 = set(sanitized_account_2_list).difference(set(sanitized_account_1_list))


        true_diff_account_1_with_common = [tup for tup in account_1_diff_items_account_2 if (tup[0] in [item[0] for item in common_role_list])]
        print("There are %d items that are in different in %s among common roles between %s,%s" %(len(true_diff_account_1_with_common),self.account_1_tag, self.account_1_tag,self.account_2_tag))
        headerrow =('rolename', 'path','trust', 'policyname', 'effect', 'service', 'action', 'arn')
        filename = self.account_1_tag + "_to_" + self.account_2_tag + "_common_role_difference_items.csv"
        self.write_to_csv(true_diff_account_1_with_common, headerrow, filename)

        true_diff_role_account_1_with_common = set([(item[0],) for item in true_diff_account_1_with_common])
        print("There are %d common roles in %s that have differences with %s "%(len(true_diff_role_account_1_with_common), self.account_1_tag, self.account_2_tag))
        headerrow =('rolename',)
        filename = "common_roles_in_" + self.account_1_tag + "_with_differences" + ".csv"
        self.write_to_csv(true_diff_role_account_1_with_common, headerrow, filename)

        # base_diff_account_2_with_common = [tup for tup in account_2 if (tup[0] in common_role_list)]
        # print("Number of items in " + account2tag + " tied to common roles: " + str(len(base_diff_account_2_with_common)))
        true_diff_account_2_with_common = [tup for tup in account_2_diff_items_account_1 if (tup[0] in [item[0] for item in common_role_list])]
        print("There are %d items that are in different in %s among common roles between %s,%s" %(len(true_diff_account_2_with_common), self.account_2_tag, self.account_1_tag, self.account_2_tag))
        headerrow =('rolename', 'path','trust', 'policyname', 'effect', 'service', 'action', 'arn')
        filename = self.account_2_tag + "_to_" + self.account_1_tag + "_common_role_difference_items.csv"
        self.write_to_csv(true_diff_account_2_with_common, headerrow, filename)
        
        true_diff_role_account_2_with_common = set([(item[0],) for item in true_diff_account_2_with_common])
        print("There are %d common roles in %s that have differences with %s "%(len(true_diff_role_account_2_with_common), self.account_2_tag, self.account_1_tag))
        headerrow = ('rolename',)
        filename = "common_roles_in_" + self.account_2_tag + "_with_differences" + ".csv"
        self.write_to_csv(true_diff_role_account_2_with_common, headerrow, filename)

        summary.append(['Common Roles with Differences', len(true_diff_role_account_1_with_common), len(true_diff_role_account_2_with_common)])
        summary.append(['Differences among Common Roles', len(true_diff_account_1_with_common), len(true_diff_account_2_with_common)])

        print(Style.BRIGHT)
        print(Fore.YELLOW +"Summary report in tabular format:")
        print(Style.RESET_ALL)

        table = SingleTable(summary)
        table.title = "Summary Report"
        table.inner_heading_row_border = True
        table.inner_row_border = True
        table.justify_columns[1] = 'right'
        table.justify_columns[2] = 'right'
        print(table.table)

        print(Style.BRIGHT)
        print(Fore.GREEN + "Detailed reports are available at this location:\n%s" %(self.output_directory))
        print(Style.RESET_ALL)
