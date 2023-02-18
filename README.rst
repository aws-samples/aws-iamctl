AWS IAM role-comparison tool IAMCTL

Summary
-------

IAMCTL is a tool that you can use to extract the IAM roles and policies from two accounts, 
compare them, and report out the differences and statistics. We will explain how to use the 
tool, and will describe the key concepts so you can configure it to programmatically run 
against all of your AWS accounts.

Prerequisites
-------------

Before you install the tool and start using it, here are few
prerequisites that need to be in place on the computer where you will
run the tool.

-  `Python 3.x <https://www.python.org/downloads/>`__

-  `Git <https://git-scm.com/book/en/v2/Getting-Started-Installing-Git>`__

-  `AWS Command Line Interface
   (CLI) <https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html>`__

-  Setup AWS CLI profiles for the two accounts you want to compare, as
   described in `Named
   Profiles <https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html>`__.

To follow along in your environment, download the files from the GitHub
repository, and run the steps in order. You will not incur any charges
to run this tool.

Install the IAMCTL tool
-----------------------

This section describes how to install and run the IAMCTL tool.

1. At the command line, enter the following command:

pip install git+ssh://git@github.com/aws-samples/aws-iamctl.git

You will see output similar to the following:

|image0|

Figure 1: IAMCTL tool installation output

2. To confirm that your installation was successful, enter the following
   command:

iamctl –h

   You will see results like the following:

|image1|

Figure 2: IAMCTL help message

   Now that you have successfully installed the IAMCTL tool, the next
   section will show you how to use the IAMCTL commands.

Run the IAMCTL tool
-------------------

Initializing IAMCTL
~~~~~~~~~~~~~~~~~~~

| To run the IAMCTL tool, initialize using the init command. The init
  command does not need any additional input parameters, and uses the
  following syntax:
| iamctl init

   **Important**: It is recommended that you run the init command before
   you use the IAMCTL tool, and for every subsequent use, to ensure that
   the most up-to-date AWS service-specific metadata is available for
   the tool for running other commands such as harvest and diff.

   If your init command run is successful, you will see output similar
   to the following screenshot.

|image2|

Figure 3: Successful initialization output

   The init command creates two files in the directory where you run the
   command. First, it downloads iam.json, which contains IAM
   service-specific actions, conditions, and the resource ARN regex
   available from a `public S3 bucket used by the AWS Policy Generator
   tool <https://awspolicygen.s3.amazonaws.com/js/policies.js>`__.

   Second, the init command creates equivalency_list.json, which is an
   equivalency list JSON file that can be used to store known prefix,
   suffix, and other string patterns that are unique to your account and
   are considered equal.

   For example, if you have a role named my-app-1-prod in your
   production account, and a role named my-app-1-dev in your development
   account, you can specify prod and dev strings in the equivalency
   dictionary as shown in the following example, so that all occurrences
   of those strings will be substituted with accountprefix1.

|image3|

Figure 4: Example equivalency list

Harvest profiles
~~~~~~~~~~~~~~~~

   The harvest command extracts IAM roles and policies from the AWS
   account, as specified in the <cli-profile>, and then writes it out to
   a CSV file.

   The harvest command also does two additional processing steps. First,
   it expands glob patterns in actions to the full list of
   service-specific actions. Second, it matches up the resource to a
   specific-service action. The CSV file with extracted data has the
   format as shown in the following example.

   |image4|

   Figure 5: Example CSV file with extracted data

   We will go into further explanation of each column and row in this
   CSV file later in this blog post

   The following screenshot shows the output of the harvest command help
   option, which includes the input arguments necessary and a brief
   explanation about each option.

|image5|

Figure 6: Harvest command help option

The harvest command uses the following syntax:

iamctl harvest <cli-profile> <account-tag>

   When you run the harvest command, you should see output similar to
   the following screenshot.

|image6|

Figure 7: Example output from harvest command

   You should now be able to see a file created with name
   <account-tag>_<cli-profile>_iam_tuples.csv in the following directory
   path:

<*user home>*/aws-idt/output/YYYY/mm/dd/HH/MM/SS/.

   The harvest command is useful for use cases where you want to get a
   snapshot of all IAM roles and profiles from an AWS account, and
   consume it for further processing. Because the extract is flattened
   out and expanded, it can be used in reports and analysis, as you
   need.

All files written to disk by the IAMCTL tool are written to the
following location, which includes a time-based directory structure:

<*user home>*/aws-idt/output/YYYY/mm/dd/HH/MM/SS/

The time-based directory structure allows you to periodically run the
**harvest** command, and have it create an archive over time.

Compare harvested profiles with the diff command
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The diff command compares two accounts to determine differences in IAM
role definitions. The diff command considers a role from each account
for comparison, based on name. The equivalency list populated when you
run the init command is used to ensure that two roles that have known
string patterns in the name that are different between the two accounts
do get picked up for comparison. Comparison results are written out to
disk among multiple files. The naming convention for these files, and
the context of what is written to each of them is explained later in
this blog post.

The following screenshot shows the output of the diff command help
option, which includes the input arguments necessary and a brief
explanation about each option.

|image7|

Figure 8: diff command help option

The diff command uses the following syntax:

iamctl diff cli_profile_1 account_tag_1 cli_profile_2 account_tag_2

The following screenshot shows the execution of the diff command, along
with the processing status and summary reports of the two profiles.

|image8|

Figure 9: diff command execution output

Interpret the results and find differences
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Here is a detailed explanation of what the diff command does, and how to
interpret the results, so that you can find the differences between IAM
roles from the two accounts.

Step-1: Harvest 
''''''''''''''''

The diff command relies on the harvest command to extract IAM data from
each of the two accounts. You can see the number of roles in each
account, and the estimated time remaining is indicated in a progress bar
as shown in the previous example.

Two extract files from this step are written to disk to the output
directory. The following table shows the naming convention, and a brief
description of each.

============================================== ==================================
File Name                                      Description
============================================== ==================================
<account_tag_1>_<cli_profile_1>_iam_tuples.csv IAM items extracted from Account-1
<account_tag_2>_<cli_profile_2>_iam_tuples.csv IAM items extracted from Account-2
============================================== ==================================

Step-2: Diff 
'''''''''''''

The diff command compares the two extracts generated (one from each
account), then reads in the equivalency list populated from the init
command to reduce false positives. The diff command returns summary
information of all the differences to the output screen, and writes the
full difference information to disk.

The 19 diff files from this step are written to disk in the output
directory. The following table shows the file naming convention, and a
brief description of each.

========================================================================== ==================================================================================================================
File Name                                                                  Description
========================================================================== ==================================================================================================================
<account_tag_1>_roles.csv                                                  List of roles from Account-1.
<account_tag_1>_non_service_linked_roles.csv                               List of non service-linked roles from Account-1.
<account_tag_1>_service_linked_roles.csv                                   List of service-linked roles from Account-1.
<account_tag_2>_roles.csv                                                  List of roles from Account-2.
<account_tag_2>_non_service_linked_roles.csv                               List of non service-linked roles from Account-2.
<account_tag_2>_service_linked_roles.csv                                   List of service-linked roles from Account-2.
common_roles.csv                                                           List of common roles between Account-1 and Account-2. A common role is a role with the same name in both accounts.
common_service_linked_roles.csv                                            List of common service-linked roles between Account-1 and Account-2.
common_non_service_linked_roles.csv                                        List of common non service-linked roles between Account-1 and Account-2.
<account_1_tag>_to_<account_2_tag>_common_role_difference_items.csv        List of IAM items from common roles that are in Account-1, but not in Account-2.
<account_2_tag>_to_<account_1_tag>_common_role_difference_items.csv        List of IAM items from common roles that are in Account-2, but not in Account-1.
common_roles_in_<account_tag_1>_with_differences.csv                       List of IAM roles in Account-1 that are common to both accounts, but have differences.
common_roles_in_<account_tag_2>_with_differences.csv                       List of IAM roles in Account-2 that are common to both accounts, but have differences.
roles_in_<account_1_tag>_but_not_in_<account_2_tag>.csv                    List of IAM roles that are unique to Account-1.
roles_in_<account_2_tag>_but_not_in_<account_1_tag>.csv                    List of IAM roles that are unique to Account-2.
service_linked_roles_in_<account_1_tag>_but_not_in_<account_2_tag>.csv     List of service-linked IAM roles that are unique to Account-1.
service_linked_roles_in_<account_2_tag>_but_not_in_<account_1_tag>.csv     List of service-linked IAM roles that are unique to Account-2.
non_service_linked_roles_in_<account_1_tag>_but_not_in_<account_2_tag>.csv List of non service-linked IAM roles that are unique to Account-1.
non_service_linked_roles_in_<account_2_tag>_but_not_in_<account_1_tag>.csv List of non service-linked IAM roles that are unique to Account-2.
========================================================================== ==================================================================================================================

How to interpret the output tables 
-----------------------------------

Both the harvest and diff commands write out *IAM items*. An IAM item is
each row of a two-dimensional table that results from flattening an IAM
role into its constituent components, and mapping each attribute to a
column of that table, as shown in the following diagram. An IAM role can
have multiple policies associated with it. For more information, see the
`IAM User
Guide <https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html>`__.

|image9|

Figure 10: Example of IAM Role with various policies flattened into IAM
items

The following table shows attributes of an IAM Item and a brief
definition of each.

=============== ====================================================================================
Attribute name  Definition
=============== ====================================================================================
Role Name       Name of the IAM role.
Policy          Name of the IAM policy.
Policy Type     One of the values: “Inline”, “Managed”, “Trust”
Effect          IAM Statement effect: “Allow”, “Deny”
Service         Service name
Action          Action within the service
Trust Principal Principal that is trusted to assume this role, populated only for Policy Type Trust.
=============== ====================================================================================

The following screenshot shows the console output for the diff command
run against two example accounts.

|image10|

Figure 10: Example output for the diff command run against two accounts

The following table provides an explanation for each metric from the
summary report in tabular format in the previous example.

=============================== ======================================================================================================================================
Metric                          Definition
=============================== ======================================================================================================================================
Harvested items                 Count of *IAM item*\ s. See earlier for detailed explanation of an *IAM Item*.
Sanitized items                 Count of *IAM item*\ s after applying the equivalency dictionary.
Roles                           Count of IAM roles.
Service linked roles            Count of IAM roles with a “/aws-service-role/” path.
Non-Service linked roles        Count of IAM roles without a “/aws-service-role/” path.
Common roles                    Count of IAM roles that are similar by name from both accounts, specified as parameters for diff.
Common service linked roles     Count of IAM roles with a “/aws-service-role/” path, that are similar by name from both accounts, specified as parameters for diff.
Common Non-Service linked roles Count of IAM roles without a “/aws-service-role/” path, that are similar by name from both accounts, specified as parameters for diff.
Unique roles                    Count of IAM roles that exist only in that account, based on name as compared to the other account.
Unique service linked roles     Count of service-linked roles that exist only in that account, based on name as compared to the other account.
Unique non-service linked roles Count of non-service-linked roles that exist only in that account, based on name as compared to the other account.
Common roles with differences   Count of roles that are common to both accounts, based on name, but have differences as seen in any of the *IAM item*\ s.
Differences among common roles  Count of *IAM items* among common roles that are different, as seen from this account compared to the other account.
=============================== ======================================================================================================================================

The diff command output presents both summarized statistics and granular
lists, which allow you to see the number of deviations between two
accounts, and also provide actionable output to help you remediate these
differences.

Conclusion:
-----------

You have learnt how to use the IAMCTL tool to compare IAM
roles between two accounts, to arrive at a granular list of meaningful
differences that can be used for compliance audits or for further
remediation actions. If you have created your IAM roles using a
CloudFormation stack, you can turn on drift detection and easily capture
the drift because of changes done outside of CloudFormation to those IAM
resources. For more information about drift detection, see `Detecting
Unmanaged Configuration Changes to Stacks and
Resources <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-drift.html>`__.
we welcome any pull requests for issues and enhancements.

.. |image0| image:: .//media/image1.png
   :width: 6.5in
   :height: 1.01528in
.. |image1| image:: .//media/image2.png
   :width: 5.86368in
   :height: 6.29878in
.. |image2| image:: .//media/image3.png
   :width: 6.5in
   :height: 2.39028in
.. |image3| image:: .//media/image4.png
   :width: 5.26153in
   :height: 3.55088in
.. |image4| image:: .//media/image5.png
   :width: 6.5in
   :height: 0.61319in
.. |image5| image:: .//media/image6.png
   :width: 6.5in
   :height: 3.03542in
.. |image6| image:: .//media/image7.png
   :width: 6.5in
   :height: 1.5848in
.. |image7| image:: .//media/image8.png
   :width: 6.5in
   :height: 3.40417in
.. |image8| image:: .//media/image9.png
   :width: 6.5in
   :height: 2.07917in
.. |image9| image:: .//media/image10.png
   :width: 6.5in
   :height: 2.8296in
.. |image10| image:: .//media/image11.png
   :width: 5.48611in
   :height: 9in
