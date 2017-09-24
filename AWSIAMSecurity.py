from __future__ import print_function
import json
import csv
import time
import sys
import re
import tempfile
import getopt
import os
from datetime import datetime
import boto3


# --- Script controls ---

# CIS Benchmark version referenced. Only used in web report.
AWS_CIS_BENCHMARK_VERSION = "1.1"

# Would you like to print the results as JSON to output?
SCRIPT_OUTPUT_JSON = True


# --- Control Parameters ---

# Control 1.18 - IAM manager and master role names <Not implemented yet, under review>
IAM_MASTER = "iam_master"
IAM_MANAGER = "iam_manager"
IAM_MASTER_POLICY = "iam_master_policy"
IAM_MANAGER_POLICY = "iam_manager_policy"

# Control 1.1 - Days allowed since use of root account.
CONTROL_1_1_DAYS = 0


# --- Global ---
IAM_CLIENT = boto3.client('iam')
S3_CLIENT = boto3.client('s3')


# --- 1 Identity and Access Management ---

# 1.1 Avoid the use of the "root" account (Scored)
def control_1_1_root_use(credreport):
    """Summary

    Args:
        credreport (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.1"
    description = "Avoid the use of the root account"
    scored = True
    if "Fail" in credreport:  # Report failure in control
        sys.exit(credreport)
    # Check if root is used in the last 24h
    now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
    frm = "%Y-%m-%dT%H:%M:%S+00:00"

    try:
        pwdDelta = (datetime.strptime(now, frm) - datetime.strptime(credreport[0]['password_last_used'], frm))
        if (pwdDelta.days == CONTROL_1_1_DAYS) & (pwdDelta.seconds > 0):  # Used within last 24h
            failReason = "Used within 24h"
            result = False
    except:
        if credreport[0]['password_last_used'] == "N/A" or "no_information":
            pass
        else:
            print("Something went wrong")

    try:
        key1Delta = (datetime.strptime(now, frm) - datetime.strptime(credreport[0]['access_key_1_last_used_date'], frm))
        if (key1Delta.days == CONTROL_1_1_DAYS) & (key1Delta.seconds > 0):  # Used within last 24h
            failReason = "Used within 24h"
            result = False
    except:
        if credreport[0]['access_key_1_last_used_date'] == "N/A" or "no_information":
            pass
        else:
            print("Something went wrong")
    try:
        key2Delta = datetime.strptime(now, frm) - datetime.strptime(credreport[0]['access_key_2_last_used_date'], frm)
        if (key2Delta.days == CONTROL_1_1_DAYS) & (key2Delta.seconds > 0):  # Used within last 24h
            failReason = "Used within 24h"
            result = False
    except:
        if credreport[0]['access_key_2_last_used_date'] == "N/A" or "no_information":
            pass
        else:
            print("Something went wrong")
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.2 Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored)
def control_1_2_mfa_on_password_enabled_iam(credreport):
    """Summary

    Args:
        credreport (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.2"
    description = "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password"
    scored = True
    for i in range(len(credreport)):
        # Verify if the user have a password configured
        if credreport[i]['password_enabled'] == "true":
            # Verify if password users have MFA assigned
            if credreport[i]['mfa_active'] == "false":
                result = False
                failReason = "No MFA on users with password. "
                offenders.append(str(credreport[i]['arn']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.3 Ensure credentials unused for 90 days or greater are disabled (Scored)
def control_1_3_unused_credentials(credreport):
    """Summary

    Args:
        credreport (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.3"
    description = "Ensure credentials unused for 90 days or greater are disabled"
    scored = True
    # Get current time
    now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
    frm = "%Y-%m-%dT%H:%M:%S+00:00"

    # Look for unused credentails
    for i in range(len(credreport)):
        if credreport[i]['password_enabled'] == "true":
            try:
                delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['password_last_used_date'], frm)
                # Verify password have been used in the last 90 days
                if delta.days > 90:
                    result = False
                    failReason = "Credentials unused > 90 days detected. "
                    offenders.append(str(credreport[i]['arn']) + ":password")
            except:
                pass  # Never used
        if credreport[i]['access_key_1_active'] == "true":
            try:
                delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['access_key_1_last_used_date'], frm)
                # Verify password have been used in the last 90 days
                if delta.days > 90:
                    result = False
                    failReason = "Credentials unused > 90 days detected. "
                    offenders.append(str(credreport[i]['arn']) + ":key1")
            except:
                pass
        if credreport[i]['access_key_2_active'] == "true":
            try:
                delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['access_key_2_last_used_date'], frm)
                # Verify password have been used in the last 90 days
                if delta.days > 90:
                    result = False
                    failReason = "Credentials unused > 90 days detected. "
                    offenders.append(str(credreport[i]['arn']) + ":key2")
            except:
                # Never used
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.4 Ensure access keys are rotated every 90 days or less (Scored)
def control_1_4_rotated_keys(credreport):
    """Summary

    Args:
        credreport (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.4"
    description = "Ensure access keys are rotated every 90 days or less"
    scored = True
    # Get current time
    now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
    frm = "%Y-%m-%dT%H:%M:%S+00:00"

    # Look for unused credentails
    for i in range(len(credreport)):
        if credreport[i]['access_key_1_active'] == "true":
            try:
                delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['access_key_1_last_rotated'], frm)
                # Verify keys have rotated in the last 90 days
                if delta.days > 90:
                    result = False
                    failReason = "Key rotation >90 days or not used since rotation"
                    offenders.append(str(credreport[i]['arn']) + ":unrotated key1")
            except:
                pass
            try:
                last_used_datetime = datetime.strptime(credreport[i]['access_key_1_last_used_date'], frm)
                last_rotated_datetime = datetime.strptime(credreport[i]['access_key_1_last_rotated'], frm)
                # Verify keys have been used since rotation.
                if last_used_datetime < last_rotated_datetime:
                    result = False
                    failReason = "Key rotation >90 days or not used since rotation"
                    offenders.append(str(credreport[i]['arn']) + ":unused key1")
            except:
                pass
        if credreport[i]['access_key_2_active'] == "true":
            try:
                delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['access_key_2_last_rotated'], frm)
                # Verify keys have rotated in the last 90 days
                if delta.days > 90:
                    result = False
                    failReason = "Key rotation >90 days or not used since rotation"
                    offenders.append(str(credreport[i]['arn']) + ":unrotated key2")
            except:
                pass
            try:
                last_used_datetime = datetime.strptime(credreport[i]['access_key_2_last_used_date'], frm)
                last_rotated_datetime = datetime.strptime(credreport[i]['access_key_2_last_rotated'], frm)
                # Verify keys have been used since rotation.
                if last_used_datetime < last_rotated_datetime:
                    result = False
                    failReason = "Key rotation >90 days or not used since rotation"
                    offenders.append(str(credreport[i]['arn']) + ":unused key2")
            except:
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.5 Ensure IAM password policy requires at least one uppercase letter (Scored)
def control_1_5_password_policy_uppercase(passwordpolicy):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.5"
    description = "Ensure IAM password policy requires at least one uppercase letter"
    scored = True
    if passwordpolicy is False:
        result = False
        failReason = "Account does not have a IAM password policy."
    else:
        if passwordpolicy['RequireUppercaseCharacters'] is False:
            result = False
            failReason = "Password policy does not require at least one uppercase letter"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.6 Ensure IAM password policy requires at least one lowercase letter (Scored)
def control_1_6_password_policy_lowercase(passwordpolicy):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.6"
    description = "Ensure IAM password policy requires at least one lowercase letter"
    scored = True
    if passwordpolicy is False:
        result = False
        failReason = "Account does not have a IAM password policy."
    else:
        if passwordpolicy['RequireLowercaseCharacters'] is False:
            result = False
            failReason = "Password policy does not require at least one uppercase letter"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.7 Ensure IAM password policy requires at least one symbol (Scored)
def control_1_7_password_policy_symbol(passwordpolicy):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.7"
    description = "Ensure IAM password policy requires at least one symbol"
    scored = True
    if passwordpolicy is False:
        result = False
        failReason = "Account does not have a IAM password policy."
    else:
        if passwordpolicy['RequireSymbols'] is False:
            result = False
            failReason = "Password policy does not require at least one symbol"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.8 Ensure IAM password policy requires at least one number (Scored)
def control_1_8_password_policy_number(passwordpolicy):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.8"
    description = "Ensure IAM password policy requires at least one number"
    scored = True
    if passwordpolicy is False:
        result = False
        failReason = "Account does not have a IAM password policy."
    else:
        if passwordpolicy['RequireNumbers'] is False:
            result = False
            failReason = "Password policy does not require at least one number"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.9 Ensure IAM password policy requires minimum length of 14 or greater (Scored)
def control_1_9_password_policy_length(passwordpolicy):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.9"
    description = "Ensure IAM password policy requires minimum length of 14 or greater"
    scored = True
    if passwordpolicy is False:
        result = False
        failReason = "Account does not have a IAM password policy."
    else:
        if passwordpolicy['MinimumPasswordLength'] < 14:
            result = False
            failReason = "Password policy does not require at least 14 characters"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.10 Ensure IAM password policy prevents password reuse (Scored)
def control_1_10_password_policy_reuse(passwordpolicy):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.10"
    description = "Ensure IAM password policy prevents password reuse"
    scored = True
    if passwordpolicy is False:
        result = False
        failReason = "Account does not have a IAM password policy."
    else:
        try:
            if passwordpolicy['PasswordReusePrevention'] == 24:
                pass
            else:
                result = False
                failReason = "Password policy does not prevent reusing last 24 passwords"
        except:
            result = False
            failReason = "Password policy does not prevent reusing last 24 passwords"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.11 Ensure IAM password policy expires passwords within 90 days or less (Scored)
def control_1_11_password_policy_expire(passwordpolicy):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.11"
    description = "Ensure IAM password policy expires passwords within 90 days or less"
    scored = True
    if passwordpolicy is False:
        result = False
        failReason = "Account does not have a IAM password policy."
    else:
        if passwordpolicy['ExpirePasswords'] is True:
            if 0 < passwordpolicy['MaxPasswordAge'] > 90:
                result = False
                failReason = "Password policy does not expire passwords after 90 days or less"
        else:
            result = False
            failReason = "Password policy does not expire passwords after 90 days or less"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.12 Ensure no root account access key exists (Scored)
def control_1_12_root_key_exists(credreport):
    """Summary

    Args:
        credreport (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.12"
    description = "Ensure no root account access key exists"
    scored = True
    if (credreport[0]['access_key_1_active'] == "true") or (credreport[0]['access_key_2_active'] == "true"):
        result = False
        failReason = "Root have active access keys"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.13 Ensure MFA is enabled for the "root" account (Scored)
def control_1_13_root_mfa_enabled():
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.13"
    description = "Ensure MFA is enabled for the root account"
    scored = True
    response = IAM_CLIENT.get_account_summary()
    if response['SummaryMap']['AccountMFAEnabled'] != 1:
        result = False
        failReason = "Root account not using MFA"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.14 Ensure hardware MFA is enabled for the "root" account (Scored)
def control_1_14_root_hardware_mfa_enabled():
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.14"
    description = "Ensure hardware MFA is enabled for the root account"
    scored = True
    # First verify that root is using MFA (avoiding false positive)
    response = IAM_CLIENT.get_account_summary()
    if response['SummaryMap']['AccountMFAEnabled'] == 1:
        paginator = IAM_CLIENT.get_paginator('list_virtual_mfa_devices')
        response_iterator = paginator.paginate(
            AssignmentStatus='Any',
        )
        pagedResult = []
        for page in response_iterator:
            for n in page['VirtualMFADevices']:
                pagedResult.append(n)
        if "mfa/root-account-mfa-device" in str(pagedResult):
            failReason = "Root account not using hardware MFA"
            result = False
    else:
        result = False
        failReason = "Root account not using MFA"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.15 Ensure security questions are registered in the AWS account (Not Scored/Manual)
def control_1_15_security_questions_registered():
    """Summary

    Returns:
        TYPE: Description
    """
    result = "Manual"
    failReason = ""
    offenders = []
    control = "1.15"
    description = "Ensure security questions are registered in the AWS account, please verify manually"
    scored = False
    failReason = "Control not implemented using API, please verify manually"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.16 Ensure IAM policies are attached only to groups or roles (Scored)
def control_1_16_no_policies_on_iam_users():
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.16"
    description = "Ensure IAM policies are attached only to groups or roles"
    scored = True
    paginator = IAM_CLIENT.get_paginator('list_users')
    response_iterator = paginator.paginate()
    pagedResult = []
    for page in response_iterator:
        for n in page['Users']:
            pagedResult.append(n)
    offenders = []
    for n in pagedResult:
        policies = IAM_CLIENT.list_user_policies(
            UserName=n['UserName'],
            MaxItems=1
        )
        if policies['PolicyNames'] != []:
            result = False
            failReason = "IAM user have inline policy attached"
            offenders.append(str(n['Arn']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.17 Enable detailed billing (Scored)
def control_1_17_detailed_billing_enabled():
    """Summary

    Returns:
        TYPE: Description
    """
    result = "Manual"
    failReason = ""
    offenders = []
    control = "1.17"
    description = "Enable detailed billing, please verify manually"
    scored = True
    failReason = "Control not implemented using API, please verify manually"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.18 Ensure IAM Master and IAM Manager roles are active (Scored)
def control_1_18_ensure_iam_master_and_manager_roles():
    """Summary

    Returns:
        TYPE: Description
    """
    result = "True"
    failReason = "No IAM Master or IAM Manager role created"
    offenders = []
    control = "1.18"
    description = "Ensure IAM Master and IAM Manager roles are active. Control under review/investigation"
    scored = True
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.19 Maintain current contact details (Scored)
def control_1_19_maintain_current_contact_details():
    """Summary

    Returns:
        TYPE: Description
    """
    result = "Manual"
    failReason = ""
    offenders = []
    control = "1.19"
    description = "Maintain current contact details, please verify manually"
    scored = True
    failReason = "Control not implemented using API, please verify manually"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.20 Ensure security contact information is registered (Scored)
def control_1_20_ensure_security_contact_details():
    """Summary

    Returns:
        TYPE: Description
    """
    result = "Manual"
    failReason = ""
    offenders = []
    control = "1.20"
    description = "Ensure security contact information is registered, please verify manually"
    scored = True
    failReason = "Control not implemented using API, please verify manually"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.21 Ensure IAM instance roles are used for AWS resource access from instances (Scored)
def control_1_21_ensure_iam_instance_roles_used():
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.21"
    description = "Ensure IAM instance roles are used for AWS resource access from instances, application code is not audited"
    scored = True
    failReason = "Instance not assigned IAM role for EC2"
    client = boto3.client('ec2')
    response = client.describe_instances()
    offenders = []
    for n, _ in enumerate(response['Reservations']):
        try:
            if response['Reservations'][n]['Instances'][0]['IamInstanceProfile']:
                pass
        except:
                result = False
                offenders.append(str(response['Reservations'][n]['Instances'][0]['InstanceId']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.22 Ensure a support role has been created to manage incidents with AWS Support (Scored)
def control_1_22_ensure_incident_management_roles():
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.22"
    description = "Ensure a support role has been created to manage incidents with AWS Support"
    scored = True
    offenders = []
    response = IAM_CLIENT.list_entities_for_policy(
        PolicyArn='arn:aws:iam::aws:policy/AWSSupportAccess'
    )
    if (len(response['PolicyGroups']) + len(response['PolicyUsers']) + len(response['PolicyRoles'])) == 0:
        result = False
        failReason = "No user, group or role assigned AWSSupportAccess"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.23 Do not setup access keys during initial user setup for all IAM users that have a console password (Not Scored)
# def control_1_23_no_active_initial_access_keys_with_iam_user(credreport):
#     """Summary
#
#     Returns:
#         TYPE: Description
#     """
#     result = True
#     failReason = ""
#     offenders = []
#     control = "1.23"
#     description = "Do not setup access keys during initial user setup for all IAM users that have a console password"
#     scored = False
#     offenders = []
#     for n, _ in enumerate(credreport):
#         if (credreport[n]['access_key_1_active'] or credreport[n]['access_key_2_active'] == 'true') and n > 0:
#             response = IAM_CLIENT.list_access_keys(
#                 UserName=str(credreport[n]['user'])
#             )
#             for m in response['AccessKeyMetadata']:
#                 if re.sub(r"\s", "T", str(m['CreateDate'])) == credreport[n]['user_creation_time']:
#                     result = False
#                     failReason = "Users with keys created at user creation time found"
#                     offenders.append(str(credreport[n]['arn']) + ":" + str(m['AccessKeyId']))
#     return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.24  Ensure IAM policies that allow full "*:*" administrative privileges are not created (Scored)
def control_1_24_no_overly_permissive_policies():
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.24"
    description = "Ensure IAM policies that allow full administrative privileges are not created"
    scored = True
    offenders = []
    paginator = IAM_CLIENT.get_paginator('list_policies')
    response_iterator = paginator.paginate(
        Scope='Local',
        OnlyAttached=False,
    )
    pagedResult = []
    for page in response_iterator:
        for n in page['Policies']:
            pagedResult.append(n)
    for m in pagedResult:
        policy = IAM_CLIENT.get_policy_version(
            PolicyArn=m['Arn'],
            VersionId=m['DefaultVersionId']
        )

        statements = []
        # a policy may contain a single statement, a single statement in an array, or multiple statements in an array
        if isinstance(policy['PolicyVersion']['Document']['Statement'], list):
            for statement in policy['PolicyVersion']['Document']['Statement']:
                statements.append(statement)
        else:
            statements.append(policy['PolicyVersion']['Document']['Statement'])

        for n in statements:
            # a policy statement has to contain either an Action or a NotAction
            if 'Action' in n.keys() and n['Effect'] == 'Allow':
                if ("'*'" in str(n['Action']) or str(n['Action']) == "*") and ("'*'" in str(n['Resource']) or str(n['Resource']) == "*"):
                    failReason = "Found full administrative policy"
                    result = False
                    offenders.append(str(m['Arn']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# --- Central functions ---

def get_cred_report():
    """Summary

    Returns:
        TYPE: Description
    """
    x = 0
    status = ""
    while IAM_CLIENT.generate_credential_report()['State'] != "COMPLETE":
        time.sleep(2)
        x += 1
        # If no credentail report is delivered within this time fail the check.
        if x > 10:
            status = "Fail: rootUse - no CredentialReport available."
            break
    if "Fail" in status:
        return status
    response = IAM_CLIENT.get_credential_report()
    report = []
    reader = csv.DictReader(response['Content'].splitlines(), delimiter=',')
    for row in reader:
        report.append(row)
    return report


def get_account_password_policy():
    """Check if a IAM password policy exists, if not return false

    Returns:
        Account IAM password policy or False
    """
    try:
        response = IAM_CLIENT.get_account_password_policy()
        return response['PasswordPolicy']
    except Exception as e:
        if "cannot be found" in str(e):
            return False


def get_regions():
    """Summary

    Returns:
        TYPE: Description
    """
    client = boto3.client('ec2')
    region_response = client.describe_regions()
    regions = [region['RegionName'] for region in region_response['Regions']]
    return regions


def get_cloudtrails(regions):
    """Summary

    Returns:
        TYPE: Description
    """
    trails = dict()
    for n in regions:
        client = boto3.client('cloudtrail', region_name=n)
        response = client.describe_trails()
        temp = []
        for m in response['trailList']:
            if m['IsMultiRegionTrail'] is True:
                if m['HomeRegion'] == n:
                    temp.append(m)
            else:
                temp.append(m)
        if len(temp) > 0:
            trails[n] = temp
    return trails


def find_in_string(pattern, target):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    for n in pattern:
        if not re.search(n, target):
            result = False
            break
    return result


def get_account_number():
    """Summary

    Returns:
        TYPE: Description
    """
    if S3_WEB_REPORT_OBFUSCATE_ACCOUNT is False:
        client = boto3.client("sts")
        account = client.get_caller_identity()["Account"]
    else:
        account = "111111111111"
    return account


def set_evaluation(invokeEvent, mainEvent, annotation):
    """Summary

    Args:
        event (TYPE): Description
        annotation (TYPE): Description

    Returns:
        TYPE: Description
    """
    configClient = boto3.client('config')
    if len(annotation) > 0:
        configClient.put_evaluations(
            Evaluations=[
                {
                    'ComplianceResourceType': 'AWS::::Account',
                    'ComplianceResourceId': mainEvent['accountId'],
                    'ComplianceType': 'NON_COMPLIANT',
                    'Annotation': str(annotation),
                    'OrderingTimestamp': invokeEvent['notificationCreationTime']
                },
            ],
            ResultToken=mainEvent['resultToken']
        )
    else:
        configClient.put_evaluations(
            Evaluations=[
                {
                    'ComplianceResourceType': 'AWS::::Account',
                    'ComplianceResourceId': mainEvent['accountId'],
                    'ComplianceType': 'COMPLIANT',
                    'OrderingTimestamp': invokeEvent['notificationCreationTime']
                },
            ],
            ResultToken=mainEvent['resultToken']
        )





def json_output(controlResult):
    """Summary

    Args:
        controlResult (TYPE): Description

    Returns:
        TYPE: Description
    """
    inner = dict()
    outer = dict()
    for m in range(len(controlResult)):
        inner = dict()
        for n in range(len(controlResult[m])):
            x = int(controlResult[m][n]['ControlId'].split('.')[1])
            inner[x] = controlResult[m][n]
        y = controlResult[m][0]['ControlId'].split('.')[0]
        outer[y] = inner
    if OUTPUT_ONLY_JSON is True:
        print(json.dumps(outer, sort_keys=True, indent=4, separators=(',', ': ')))
    else:
        print("JSON output:")
        print("-------------------------------------------------------")
        print(json.dumps(outer, sort_keys=True, indent=4, separators=(',', ': ')))
        print("-------------------------------------------------------")
        print("\n")
        print("Summary:")
        print(shortAnnotation(controlResult))
        print("\n")
    return 0


def shortAnnotation(controlResult):
    """Summary

    Args:
        controlResult (TYPE): Description

    Returns:
        TYPE: Description
    """
    annotation = []
    longAnnotation = False
    for m, _ in enumerate(controlResult):
        for n in range(len(controlResult[m])):
            if controlResult[m][n]['Result'] is False:
                if len(str(annotation)) < 220:
                    annotation.append(controlResult[m][n]['ControlId'])
                else:
                    longAnnotation = True
    if longAnnotation:
        annotation.append("etc")
        return "{\"Failed\":" + json.dumps(annotation) + "}"
    else:
        return "{\"Failed\":" + json.dumps(annotation) + "}"



def lambda_handler(event, context):
    """Summary

    Args:
        event (TYPE): Description
        context (TYPE): Description

    Returns:
        TYPE: Description
    """
    # Run all control validations.
    # The control object is a dictionary with the value
    # result : Boolean - True/False
    # failReason : String - Failure description
    # scored : Boolean - True/False
    # Check if the script is initiade from AWS Config Rules
    try:
        if event['configRuleId']:
            configRule = True
            # Verify correct format of event
            invokingEvent = json.loads(event['invokingEvent'])
    except:
        configRule = False

    # Globally used resources
    region_list = get_regions()
    cred_report = get_cred_report()
    password_policy = get_account_password_policy()
    cloud_trails = get_cloudtrails(region_list)
    accountNumber = get_account_number()

    # Run individual controls.
    # Comment out unwanted controls
    control1 = []
    control1.append(control_1_1_root_use(cred_report))
    control1.append(control_1_2_mfa_on_password_enabled_iam(cred_report))
    control1.append(control_1_3_unused_credentials(cred_report))
    control1.append(control_1_4_rotated_keys(cred_report))
    control1.append(control_1_5_password_policy_uppercase(password_policy))
    control1.append(control_1_6_password_policy_lowercase(password_policy))
    control1.append(control_1_7_password_policy_symbol(password_policy))
    control1.append(control_1_8_password_policy_number(password_policy))
    control1.append(control_1_9_password_policy_length(password_policy))
    control1.append(control_1_10_password_policy_reuse(password_policy))
    control1.append(control_1_11_password_policy_expire(password_policy))
    control1.append(control_1_12_root_key_exists(cred_report))
    control1.append(control_1_13_root_mfa_enabled())
    control1.append(control_1_14_root_hardware_mfa_enabled())
    control1.append(control_1_15_security_questions_registered())
    control1.append(control_1_16_no_policies_on_iam_users())
    control1.append(control_1_17_detailed_billing_enabled())
    control1.append(control_1_18_ensure_iam_master_and_manager_roles())
    control1.append(control_1_19_maintain_current_contact_details())
    control1.append(control_1_20_ensure_security_contact_details())
    control1.append(control_1_21_ensure_iam_instance_roles_used())
    control1.append(control_1_22_ensure_incident_management_roles())
    control1.append(control_1_24_no_overly_permissive_policies())


    # Join results


    controls = []
    controls.append(control1)

    # Build JSON structure for console output if enabled
    if SCRIPT_OUTPUT_JSON:
        json_output(controls)


    # Report back to Config if we detected that the script is initiated from Config Rules
    if configRule:
        evalAnnotation = shortAnnotation(controls)
        set_evaluation(invokingEvent, event, evalAnnotation)


if __name__ == '__main__':
    profile_name = ''
    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:h", ["profile=", "help"])
    except getopt.GetoptError:
        print("Error: Illegal option\n")
        print("---Usage---")
        print('Run without parameters to use default profile:')
        print("python " + sys.argv[0] + "\n")
        print("Use -p or --profile to specify a specific profile:")
        print("python " + sys.argv[0] + ' -p <profile>')
        sys.exit(2)

    # Parameter options
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print("---Help---")
            print('Run without parameters to use default profile:')
            print("python " + sys.argv[0] + "\n")
            print("Use -p or --profile to specify a specific profile:")
            print("python " + sys.argv[0] + ' -p <profile>')
            sys.exit()
        elif opt in ("-p", "--profile"):
            profile_name = arg

    # Verify that the profile exist
    if not profile_name == "":
        try:
            boto3.setup_default_session(profile_name=profile_name)
            # Update globals with new profile
            IAM_CLIENT = boto3.client('iam')
            S3_CLIENT = boto3.client('s3')
        except Exception as e:
            if "could not be found" in str(e):
                print("Error: " + str(e))
                print("Please verify your profile name.")
                sys.exit(2)

    # Test if default region is configured for the used profile, if not we will use us-east-1
    try:
        client = boto3.client('ec2')
    except Exception as e:
        if "You must specify a region" in str(e):
            if profile_name == "":
                boto3.setup_default_session(region_name='us-east-1')
            else:
                boto3.setup_default_session(profile_name=profile_name, region_name='us-east-1')
    lambda_handler("test", "test")
