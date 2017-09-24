
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
AWS_CIS_BENCHMARK_VERSION = "1.1"
S3_WEB_REPORT = True
S3_WEB_REPORT_BUCKET = "CHANGE_ME_TO_YOUR_S3_BUCKET"
S3_WEB_REPORT_NAME_DETAILS = True
S3_WEB_REPORT_EXPIRE = "168"
S3_WEB_REPORT_OBFUSCATE_ACCOUNT = False
SEND_REPORT_URL_TO_SNS = False
SNS_TOPIC_ARN = "CHANGE_ME_TO_YOUR_TOPIC_ARN"
SCRIPT_OUTPUT_JSON = True
OUTPUT_ONLY_JSON = False


# --- Control Parameters ---
IAM_MASTER = "iam_master"
IAM_MANAGER = "iam_manager"
IAM_MASTER_POLICY = "iam_master_policy"
IAM_MANAGER_POLICY = "iam_manager_policy"
CONTROL_1_1_DAYS = 0
IAM_CLIENT = boto3.client('iam')
S3_CLIENT = boto3.client('s3')


# --- Networking ---

# 4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)
def ensure_ssh_not_open_to_world(regions):
    result = True
    failReason = ""
    offenders = []
    control = "4.1"
    description = "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"
    scored = True
    for n in regions:
        client = boto3.client('ec2', region_name=n)
        response = client.describe_security_groups()
        for m in response['SecurityGroups']:
            if "0.0.0.0/0" in str(m['IpPermissions']):
                for o in m['IpPermissions']:
                    try:
                        if int(o['FromPort']) <= 22 <= int(o['ToPort']) and '0.0.0.0/0' in str(o['IpRanges']):
                            result = False
                            failReason = "Found Security Group with port 22 open to the world (0.0.0.0/0)"
                            offenders.append(str(m['GroupId']))
                    except:
                        if str(o['IpProtocol']) == "-1" and '0.0.0.0/0' in str(o['IpRanges']):
                            result = False
                            failReason = "Found Security Group with port 22 open to the world (0.0.0.0/0)"
                            offenders.append(str(n) + " : " + str(m['GroupId']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)
def ensure_rdp_not_open_to_world(regions):
    result = True
    failReason = ""
    offenders = []
    control = "4.2"
    description = "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389"
    scored = True
    for n in regions:
        client = boto3.client('ec2', region_name=n)
        response = client.describe_security_groups()
        for m in response['SecurityGroups']:
            if "0.0.0.0/0" in str(m['IpPermissions']):
                for o in m['IpPermissions']:
                    try:
                        if int(o['FromPort']) <= 3389 <= int(o['ToPort']) and '0.0.0.0/0' in str(o['IpRanges']):
                            result = False
                            failReason = "Found Security Group with port 3389 open to the world (0.0.0.0/0)"
                            offenders.append(str(m['GroupId']))
                    except:
                        if str(o['IpProtocol']) == "-1" and '0.0.0.0/0' in str(o['IpRanges']):
                            result = False
                            failReason = "Found Security Group with port 3389 open to the world (0.0.0.0/0)"
                            offenders.append(str(n) + " : " + str(m['GroupId']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 4.3 Ensure VPC flow logging is enabled in all VPCs (Scored)
def ensure_flow_logs_enabled_on_all_vpc(regions):
    result = True
    failReason = ""
    offenders = []
    control = "4.3"
    description = "Ensure VPC flow logging is enabled in all VPCs"
    scored = True
    for n in regions:
        client = boto3.client('ec2', region_name=n)
        flowlogs = client.describe_flow_logs(
            #  No paginator support in boto atm.
        )
        activeLogs = []
        for m in flowlogs['FlowLogs']:
            if "vpc-" in str(m['ResourceId']):
                activeLogs.append(m['ResourceId'])
        vpcs = client.describe_vpcs(
            Filters=[
                {
                    'Name': 'state',
                    'Values': [
                        'available',
                    ]
                },
            ]
        )
        for m in vpcs['Vpcs']:
            if not str(m['VpcId']) in str(activeLogs):
                result = False
                failReason = "VPC without active VPC Flow Logs found"
                offenders.append(str(n) + " : " + str(m['VpcId']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 4.4 Ensure the default security group of every VPC restricts all traffic (Scored)
def ensure_default_security_groups_restricts_traffic(regions):
    result = True
    failReason = ""
    offenders = []
    control = "4.4"
    description = "Ensure the default security group of every VPC restricts all traffic"
    scored = True
    for n in regions:
        client = boto3.client('ec2', region_name=n)
        response = client.describe_security_groups(
            Filters=[
                {
                    'Name': 'group-name',
                    'Values': [
                        'default',
                    ]
                },
            ]
        )
        for m in response['SecurityGroups']:
            if not (len(m['IpPermissions']) + len(m['IpPermissionsEgress'])) == 0:
                result = False
                failReason = "Default security groups with ingress or egress rules discovered"
                offenders.append(str(n) + " : " + str(m['GroupId']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 4.5 Ensure routing tables for VPC peering are "least access" (Not Scored)
def ensure_route_tables_are_least_access(regions):
    result = True
    failReason = ""
    offenders = []
    control = "4.5"
    description = "Ensure routing tables for VPC peering are least access"
    scored = False
    for n in regions:
        client = boto3.client('ec2', region_name=n)
        response = client.describe_route_tables()
        for m in response['RouteTables']:
            for o in m['Routes']:
                try:
                    if o['VpcPeeringConnectionId']:
                        if int(str(o['DestinationCidrBlock']).split("/", 1)[1]) < 24:
                            result = False
                            failReason = "Large CIDR block routed to peer discovered, please investigate"
                            offenders.append(str(n) + " : " + str(m['RouteTableId']))
                except:
                    pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 4.5 Ensure routing tables for VPC peering are "least access" (Not Scored)
def control_4_5_ensure_route_tables_are_least_access(regions):
    result = True
    failReason = ""
    offenders = []
    control = "4.5"
    description = "Ensure routing tables for VPC peering are least access"
    scored = False
    for n in regions:
        client = boto3.client('ec2', region_name=n)
        response = client.describe_route_tables()
        for m in response['RouteTables']:
            for o in m['Routes']:
                try:
                    if o['VpcPeeringConnectionId']:
                        if int(str(o['DestinationCidrBlock']).split("/", 1)[1]) < 24:
                            result = False
                            failReason = "Large CIDR block routed to peer discovered, please investigate"
                            offenders.append(str(n) + " : " + str(m['RouteTableId']))
                except:
                    pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# --- Central functions ---

def get_cred_report():
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
    try:
        response = IAM_CLIENT.get_account_password_policy()
        return response['PasswordPolicy']
    except Exception as e:
        if "cannot be found" in str(e):
            return False


def get_regions():
    client = boto3.client('ec2')
    region_response = client.describe_regions()
    regions = [region['RegionName'] for region in region_response['Regions']]
    return regions


def get_cloudtrails(regions):
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
    result = True
    for n in pattern:
        if not re.search(n, target):
            result = False
            break
    return result


def get_account_number():
    if S3_WEB_REPORT_OBFUSCATE_ACCOUNT is False:
        client = boto3.client("sts")
        account = client.get_caller_identity()["Account"]
    else:
        account = "111111111111"
    return account


def set_evaluation(invokeEvent, mainEvent, annotation):
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


def json2html(controlResult, account):
    table = []
    shortReport = shortAnnotation(controlResult)
    table.append("<html>\n<head>\n<style>\n\n.table-outer {\n    background-color: #eaeaea;\n    border: 3px solid darkgrey;\n}\n\n.table-inner {\n    background-color: white;\n    border: 3px solid darkgrey;\n}\n\n.table-hover tr{\nbackground: transparent;\n}\n\n.table-hover tr:hover {\nbackground-color: lightgrey;\n}\n\ntable, tr, td, th{\n    line-height: 1.42857143;\n    vertical-align: top;\n    border: 1px solid darkgrey;\n    border-spacing: 0;\n    border-collapse: collapse;\n    width: auto;\n    max-width: auto;\n    background-color: transparent;\n    padding: 5px;\n}\n\ntable th {\n    padding-right: 20px;\n    text-align: left;\n}\n\ntd {\n    width:100%;\n}\n\ndiv.centered\n{\n  position: absolute;\n  width: auto;\n  height: auto;\n  z-index: 15;\n  top: 10%;\n  left: 20%;\n  right: 20%;\n  background: white;\n}\n\ndiv.centered table\n{\n    margin: auto;\n    text-align: left;\n}\n</style>\n</head>\n<body>\n<h1 style=\"text-align: center;\">AWS CIS Foundation Framework</h1>\n<div class=\"centered\">")
    table.append("<table class=\"table table-inner\">")
    table.append("<tr><td>Account: " + account + "</td></tr>")
    table.append("<tr><td>Report date: " + time.strftime("%c") + "</td></tr>")
    table.append("<tr><td>Benchmark version: " + AWS_CIS_BENCHMARK_VERSION + "</td></tr>")
    table.append("<tr><td>Whitepaper location: <a href=\"https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf\" target=\"_blank\">https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf</a></td></tr>")
    table.append("<tr><td>" + shortReport + "</td></tr></table><br><br>")
    tableHeadOuter = "<table class=\"table table-outer\">"
    tableHeadInner = "<table class=\"table table-inner\">"
    tableHeadHover = "<table class=\"table table-hover\">"
    table.append(tableHeadOuter)  # Outer table
    for m, _ in enumerate(controlResult):
        table.append("<tr><th>" + controlResult[m][0]['ControlId'].split('.')[0] + "</th><td>" + tableHeadInner)
        for n in range(len(controlResult[m])):
            if str(controlResult[m][n]['Result']) == "False":
                resultStyle = " style=\"background-color:#ef3d47;\""
            elif str(controlResult[m][n]['Result']) == "Manual":
                resultStyle = " style=\"background-color:#ffff99;\""
            else:
                resultStyle = " style=\"background-color:lightgreen;\""
            table.append("<tr><th" + resultStyle + ">" + controlResult[m][n]['ControlId'].split('.')[1] + "</th><td>" + tableHeadHover)
            table.append("<tr><th>ControlId</th><td>" + controlResult[m][n]['ControlId'] + "</td></tr>")
            table.append("<tr><th>Description</th><td>" + controlResult[m][n]['Description'] + "</td></tr>")
            table.append("<tr><th>failReason</th><td>" + controlResult[m][n]['failReason'] + "</td></tr>")
            table.append("<tr><th>Offenders</th><td><ul>" + str(controlResult[m][n]['Offenders']).replace("', ", "',<br>") + "</ul></td></tr>")
            table.append("<tr><th>Result</th><td>" + str(controlResult[m][n]['Result']) + "</td></tr>")
            table.append("<tr><th>ScoredControl</th><td>" + str(controlResult[m][n]['ScoredControl']) + "</td></tr>")
            table.append("</table></td></tr>")
        table.append("</table></td></tr>")
    table.append("</table>")
    table.append("</div>\n</body>\n</html>")
    return table


def s3report(htmlReport, account):
    if S3_WEB_REPORT_NAME_DETAILS is True:
        reportName = "cis_report_" + str(account) + "_" + str(datetime.now().strftime('%Y%m%d_%H%M')) + ".html"
    else:
        reportName = "cis_report.html"
    with tempfile.NamedTemporaryFile(delete=False) as f:
        for item in htmlReport:
            f.write(item)
            f.flush()
        try:
            f.close()
            S3_CLIENT.upload_file(f.name, S3_WEB_REPORT_BUCKET, reportName)
            os.unlink(f.name)
        except Exception as e:
            return "Failed to upload report to S3 because: " + str(e)
    ttl = int(S3_WEB_REPORT_EXPIRE) * 60
    signedURL = S3_CLIENT.generate_presigned_url(
        'get_object',
        Params={
            'Bucket': S3_WEB_REPORT_BUCKET,
            'Key': reportName
        },
        ExpiresIn=ttl)
    return signedURL


def json_output(controlResult):
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


def send_results_to_sns(url):
    # Get correct region for the TopicARN
    region = (SNS_TOPIC_ARN.split("sns:", 1)[1]).split(":", 1)[0]
    client = boto3.client('sns', region_name=region)
    client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="AWS CIS Benchmark report - " + str(time.strftime("%c")),
        Message=json.dumps({'default': url}),
        MessageStructure='json'
    )


def lambda_handler(event, context):
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
    control4 = []
    control4.append(ensure_ssh_not_open_to_world(region_list))
    control4.append(ensure_rdp_not_open_to_world(region_list))
    control4.append(ensure_flow_logs_enabled_on_all_vpc(region_list))
    control4.append(ensure_default_security_groups_restricts_traffic(region_list))
    control4.append(ensure_route_tables_are_least_access(region_list))

    # Join results
    controls = []
    controls.append(control4)

    # Build JSON structure for console output if enabled
    if SCRIPT_OUTPUT_JSON:
        json_output(controls)

    # Create HTML report file if enabled
    if S3_WEB_REPORT:
        htmlReport = json2html(controls, accountNumber)
        if S3_WEB_REPORT_OBFUSCATE_ACCOUNT:
            for n, _ in enumerate(htmlReport):
                htmlReport[n] = re.sub(r"\d{12}", "111111111111", htmlReport[n])
        signedURL = s3report(htmlReport, accountNumber)
        if OUTPUT_ONLY_JSON is False:
            print("SignedURL:\n" + signedURL)
        if SEND_REPORT_URL_TO_SNS is True:
            send_results_to_sns(signedURL)

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