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
import fnmatch
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

class Harvester:

    def close_file_handler(self):
        self.extract_file.close()

    def read_iam_file(self):
        with open('iam.json') as json_file:  
            return json.load(json_file)

    def return_service_iam_actions(self,service_prefix):
        for p in self.iam_reference['serviceMap']:
            if (self.iam_reference['serviceMap'][p]['StringPrefix'] == service_prefix):
                return self.iam_reference['serviceMap'][p]['Actions']

    def return_service_arns(self):
        arns=[]
        for p in self.iam_reference['serviceMap']:
            if ('ARNRegex' in self.iam_reference['serviceMap'][p]):
                arns.append({'ARNRegex':self.iam_reference['serviceMap'][p]['ARNRegex'], 'StringPrefix':self.iam_reference['serviceMap'][p]['StringPrefix']})
        return arns

    def match_action_regex(self, match_action, service_prefix):
        matches = []
        actions = self.return_service_iam_actions(service_prefix)
        for action in actions or []:
            if fnmatch.fnmatch(action, match_action):
                matches.append(action)
        return matches        


    def match_resource_regex(self, match_resource):
        matches = []
        arns = self.return_service_arns()
        for arn in arns or []:
            arn_regex = re.compile(arn['ARNRegex'])
            if arn_regex.match(match_resource):
                matches.append(arn)
        return matches


    def get_iam_roles(self):
        paginator = self.client.get_paginator('list_roles')
        response_iterator = paginator.paginate( 
            PaginationConfig = {
                'PageSize': 1000,
                'StartingToken': None})
        
        roles = response_iterator.build_full_result()
        self.logger.info("Number of roles: %d",len(roles['Roles']))
        return roles['Roles']


    def get_role_inline_policies(self, role_name):
        return self.client.list_role_policies(
            RoleName = role_name
        )


    def get_role_attached_policies(self, role_name):

        return self.client.list_attached_role_policies(
            RoleName = role_name
        )

    def get_policy(self, policy_arn):
        return self.client.get_policy(PolicyArn = policy_arn)

    def get_policy_version(self,policy_arn, version_id):
        return self.client.get_policy_version(PolicyArn = policy_arn, VersionId = version_id)

    def get_role_policy(self, rolename, inline_policy_name):
        return self.client.get_role_policy(RoleName = rolename, PolicyName = inline_policy_name)

    def get_role(self, role_name):
        return self.client.get_role(RoleName = role_name)

    def parse_statement_action(self,action_tag ,statement_action):
        actions = []

        if(statement_action == "*"):
            self.logger.info("All Actions against all Services")
            actions.append({'service':'*' , action_tag:'*'})
        else:
            self.logger.debug("Statement Action: " + statement_action)
            self.logger.debug(action_tag+": " + statement_action.encode("utf-8").decode().split(':')[1])
            self.logger.debug("service: " + statement_action.encode("utf-8").decode().split(':')[0])
            action_matches = self.match_action_regex(statement_action.encode("utf-8").decode().split(':')[1], statement_action.encode("utf-8").decode().split(':')[0])
            for action in action_matches or []:
                actions.append({'service' : statement_action.encode("utf-8").decode().split(':')[0], action_tag:action})
                self.logger.info("Statement Action: " + statement_action.encode("utf-8").decode().split(':')[0]+" : " + action )
        return actions

    def parse_statement_resource(self,resource_tag, statement_resource):
        resources = []
        if(statement_resource == "*"):
            self.logger.info("All resources for all Services")
            resources.append({'service' : '*' , resource_tag : '*'})
        else:
            resource_matches = self.match_resource_regex(statement_resource)
            for resource in resource_matches:
                resources.append({'service' : resource['StringPrefix'], resource_tag : statement_resource})
                self.logger.info("Statement Resource: " + resource['StringPrefix'] + " : " + statement_resource)

        return resources

    def mux(self,action_tag,actions,resource_tag,resources):
        #actions structure is: service, action
        #resources sturcture is: service, arn
        #muxedup structure is: service, action, arn
        self.logger.debug("I am muxed up and I received this actions:")
        self.logger.debug(str(actions))
        self.logger.debug("I am muxed up and I received this resources:")
        self.logger.debug(str(resources))
        muxedup=[]
        for action in actions:
            for resource in resources:
                if ((action['service'] == resource['service']) or (action['service'] == "*") or (resource['service'] == "*")):
                    muxedup.append({'service': action['service'], 'action' : action[action_tag], 'arn' : resource[resource_tag]})  
        
        return muxedup


    def parse_policy(self,policy_document):
        # instantiate empty policy array and policy statement array
        policy_statement_array = []
        parsed_policy = []

        # determining if there is a single statement or an array of statements in the policy document 
        # and appending those statement(s) to policy_statement_array
        #
        if not isinstance(policy_document['Statement'], list):
            policy_statement_array.append(policy_document['Statement'])
        else:
            policy_statement_array = policy_document['Statement']

        # code that parses each policy statement into its components 
        # and calls parse_statement_action for action/notaction, parse_statement_resource for resource/notresource block
        for policy_statement in policy_statement_array:
            self.logger.info("Statement Effect: "+policy_statement['Effect'])
            actions = []
            statement_has_action = 'Action'
            # Checking if statement has action or notaction block
            if policy_statement.get('Action',False):
                statement_has_action = 'Action'
            else:
                statement_has_action = 'NotAction'
            # checking if Action is single item or a list
            if not isinstance(policy_statement[statement_has_action], list):
                actions=actions + self.parse_statement_action(statement_has_action, policy_statement[statement_has_action])
            else:    
                for statement_action in policy_statement[statement_has_action]:
                    actions = actions+self.parse_statement_action(statement_has_action, statement_action)


            
            resources=[]
            statement_has_resource = 'Resource'
            # Checking if statment has resource or notresource block
            if policy_statement.get('Resource',False):
                statement_has_resource = 'Resource'
            else:
                statement_has_resource = 'NotResource'
            self.logger.debug("Statement Resource: "+str(policy_statement[statement_has_resource]))
            if not isinstance(policy_statement[statement_has_resource], list):
                resources=resources+self.parse_statement_resource(statement_has_resource, policy_statement[statement_has_resource])
            else:    
                for statement_resource in policy_statement[statement_has_resource]:
                    resources = resources + self.parse_statement_resource(statement_has_resource, statement_resource)
            
            muxed_up=self.mux(statement_has_action,actions,statement_has_resource,resources)
            self.logger.debug("Going to print Muxed up results for: ")
            self.logger.debug(str(muxed_up))
            parsed_policy.append({'effect' : policy_statement['Effect'], 'action_resources' : muxed_up })
        return parsed_policy

    def write_out_exhaust(self, role):

        #self.logger.info("here is the exhaust",str(exhaust))
        #exhaust: data: List<role>
        #role: rolename:string,trust:string,parsed_policies: List<policy>
        #policy: policyname: string, parsed_statements: List<statement>
        #statement: effect: string, action_resources: List<action_resource>
        #action_resource: service, action, arn
        #Final write out (vsad, somesuffix, trust, policyname, effect, service, action, resource)
        #MVP write out (rolename, trust, policyname, effect, service, action, resource)
        csv_out = self.csv_out
        

        for policy in role['policies']:
            self.logger.info("here is the policy",str(policy))
            if policy['type'] == "trust":
                for statement in policy['statements']:
                    csv_out.writerow((role['name'],role['path'],policy['name'],policy['type'], statement['effect'],statement['service'], statement['action'], None ,statement['principal']))
            
            else:
                for statement in policy['statements']:
                    for action_resource in statement['action_resources']:
                        csv_out.writerow((role['name'], role['path'], policy['name'], policy['type'], statement['effect'], action_resource['service'], action_resource['action'], action_resource['arn'], None))

    def get_role_trust(self, roleresponse):
        trustlist = []
        for Statement in roleresponse['Statement']:
            for principal in Statement['Principal'].values():
                if isinstance(principal, list):
                    for subvalue in principal:
                        trustlist.append({'effect' : Statement['Effect'], 'service' : 'sts', 'action' : 'AssumeRole', 'principal' : subvalue})
                else:
                    trustlist.append({'effect' : Statement['Effect'], 'service' : 'sts', 'action' : 'AssumeRole', 'principal' : principal})

        self.logger.info(trustlist)                
        return {'name': 'trust', 'type' : 'trust', 'statements' : trustlist}

    def process_role_attached_policies(self, attached_policies):
        parsed_attached_policies = []
        for attached_policy in attached_policies:
            policyresponse = self.get_policy(attached_policy['PolicyArn'])['Policy']
            self.logger.debug(str(policyresponse))
            policyversion = self.get_policy_version(attached_policy['PolicyArn'], policyresponse['DefaultVersionId'])['PolicyVersion']
            policy_document = policyversion['Document']
            
            self.logger.info("Attached Policy Name: " + attached_policy['PolicyName'])
            
            self.logger.debug(str(policy_document))
            parsed_policy = self.parse_policy(policy_document)
            parsed_attached_policies.append({'name': attached_policy['PolicyName'], 'type' : 'managed', 'statements' : parsed_policy})
        return parsed_attached_policies

    def process_role_inline_policies(self, rolename, inline_policies):
        parsed_attached_policies = []
        for inline_policy_name in inline_policies:
            policyresponse = self.get_role_policy(rolename, inline_policy_name)
            policy_document = policyresponse['PolicyDocument']

            self.logger.info("Inline Policy Name: " + inline_policy_name)

            self.logger.debug(str(policy_document))
            parsed_policy = self.parse_policy(policy_document)
            parsed_attached_policies.append({'name': inline_policy_name, 'type' : 'inline', 'statements' : parsed_policy})
        return parsed_attached_policies

    def get_role_trust_policies(self, role_name):
        parsed_trust_policies=[]
        roleresponse= self.get_role(role_name )
        self.logger.info("Going to print the trust policy next")
        self.logger.debug(str(roleresponse['Role']['AssumeRolePolicyDocument']))
        trustresponse = self.get_role_trust(roleresponse['Role']['AssumeRolePolicyDocument'])
        self.logger.info("Going to print the trust policy next again")
        self.logger.info(trustresponse)
        parsed_trust_policies.append(trustresponse)

        return parsed_trust_policies

    def process_role(self, role):
        parsed_policies = []
        self.logger.info("\nRole Name: " + role['RoleName'])

        #tbd call trust policies processor
        trust_policy = self.get_role_trust_policies(role['RoleName'])
        self.logger.debug("Going to print Processed Trust Policy")
        self.logger.debug(str(trust_policy))
        parsed_policies.extend(trust_policy)

        inline_policies = self.get_role_inline_policies(role['RoleName'])['PolicyNames']
        self.logger.debug("Going to print Raw Inline Policies")
        self.logger.debug(str(inline_policies))
        processed_inline_policies=self.process_role_inline_policies(role['RoleName'], inline_policies)
        self.logger.debug("Going to print Processed Inline Policies")
        self.logger.debug(str(processed_inline_policies))
        parsed_policies.extend(processed_inline_policies)

        attached_policies = self.get_role_attached_policies(role['RoleName'])['AttachedPolicies']
        self.logger.debug("Going to print Raw Attached Policies")
        self.logger.debug(str(attached_policies))
        processed_attached_policies = self.process_role_attached_policies(attached_policies)
        self.logger.debug("Going to print Processed Attached Policies")
        self.logger.debug(str(processed_attached_policies))
        parsed_policies.extend(processed_attached_policies)
        return parsed_policies

    def harvest_iam_roles_from_account(self):
        roles=self.get_iam_roles()
        self.logger.info("Number of roles: %d", len(roles))
        #bar = ProgressBar('Something')
        bar = ChargingBar('Harvesting IAM Roles from '+self.account_tag, max=len(roles),suffix='%(index)d/%(max)d - %(eta)ds')
        for role in roles:
            parsed_policies = self.process_role(role)        
            self.write_out_exhaust({'name': role['RoleName'],'path':role['Path'],'policies':parsed_policies})
            bar.next()
        self.close_file_handler()
        bar.finish()

    def __init__(self, cli_profile_name, account_tag, output_directory):
        # create self.logger, TBD change this to get logging conf based on class name
        self.logger = logging.getLogger(__name__)
        self.iam_reference = self.read_iam_file()
        self.cli_profile_name = cli_profile_name
        self.account_tag = account_tag
        self.output_directory = output_directory
        # Any clients created from this session will use credentials
        # from the [dev] section of ~/.aws/credentials.
        self.client = boto3.Session(profile_name=cli_profile_name).client('iam')

        self.filename = self.output_directory + '/' + account_tag + '_' + cli_profile_name + '_iam_tuples.csv'
        self.extract_file = open(self.filename, "w", newline = '')
        self.csv_out = csv.writer(self.extract_file)
        self.csv_out.writerow(('rolename', 'path', 'policyname', 'policytype', 'effect', 'service', 'action', 'arn', 'principal'))