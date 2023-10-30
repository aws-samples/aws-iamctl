#   Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
  
#   Licensed under the Apache License, Version 2.0 (the "License").
#   You may not use this file except in compliance with the License.
#   A copy of the License is located at
  
#       http://www.apache.org/licenses/LICENSE-2.0
  
#   or in the "license" file accompanying this file. This file is distributed 
#   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either 
#   express or implied. See the License for the specific language governing 
#   permissions and limitations under the License.

from setuptools import setup

def readme():
    with open('README.rst', encoding="utf8") as f:
        return f.read()

requires = [
    'boto3==1.28.73',
    'botocore==1.31.73',
    'colorama==0.4.1',
    'docutils==0.14',
    'jmespath==0.9.4',
    'progress==1.5',
    'pyfiglet==0.8.post1',
    'python-dateutil==2.8.0',
    's3transfer==0.7.0',
    'setuptools-scm==3.3.3',
    'six==1.12.0',
    'terminaltables==3.1.0',
    'urllib3==2.0.7'
]

setup(name='iamctl',
      use_scm_version=True,
      setup_requires=['setuptools_scm'],
      #version='0.0.1',
      description='IAMCTL is a tool built to make it easy to export, compare and analyze AWS IAM Roles, policies across accounts. Helpful for Auditing, Archiving. See below for more use-case specific commands and their requirements. Uses AWS Boto3 SDK and AWS CLI profiles',
      long_description=readme(),
      keywords='aws account roles policy iam harvester differ',
      url='https://github.com/aws-samples/aws-iam-ctl',
      author='Sudhir Reddy Maddulapally & Soumya Vanga',
      author_email='maddulap@amazon.com, souvanga@amazon.com',
      license='Apache-2.0',
      install_requires=requires,
      packages=['iamctl'],
      zip_safe=False,
      scripts=['bin/iamctl'],
      include_package_data=True
             )
