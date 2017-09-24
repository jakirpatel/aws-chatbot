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

# --- 2 Logging ---

# 2.1 Ensure CloudTrail is enabled in all regions (Scored)
def ensure_cloud_trail_all_regions(cloudtrails):
    """Summary
    Args:
        cloudtrails (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = False
    failReason = ""
    offenders = []
    control = "2.1"
    description = "Ensure CloudTrail is enabled in all regions"
    scored = True
    for m, n in cloudtrails.iteritems():
        for o in n:
            if o['IsMultiRegionTrail']:
                client = boto3.client('cloudtrail', region_name=m)
                response = client.get_trail_status(
                    Name=o['TrailARN']
                )
                if response['IsLogging'] is True:
                    result = True
                    break
    if result is False:
        failReason = "No enabled multi region trails found"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 2.2 Ensure CloudTrail log file validation is enabled (Scored)
def ensure_cloudtrail_validation(cloudtrails):
    """Summary
    Args:
        cloudtrails (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "2.2"
    description = "Ensure CloudTrail log file validation is enabled"
    scored = True
    for m, n in cloudtrails.iteritems():
        for o in n:
            if o['LogFileValidationEnabled'] is False:
                result = False
                failReason = "CloudTrails without log file validation discovered"
                offenders.append(str(o['TrailARN']))
    offenders = set(offenders)
    offenders = list(offenders)
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 2.3 Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)
def ensure_cloudtrail_bucket_not_public(cloudtrails):
    """Summary
    Args:
        cloudtrails (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "2.3"
    description = "Ensure the S3 bucket CloudTrail logs to is not publicly accessible"
    scored = True
    for m, n in cloudtrails.iteritems():
        for o in n:
            #  We only want to check cases where there is a bucket
            if "S3BucketName" in str(o):
                try:
                    response = S3_CLIENT.get_bucket_acl(Bucket=o['S3BucketName'])
                    for p in response['Grants']:
                        # print("Grantee is " + str(p['Grantee']))
                        if re.search(r'(global/AllUsers|global/AuthenticatedUsers)', str(p['Grantee'])):
                            result = False
                            offenders.append(str(o['TrailARN']) + ":PublicBucket")
                            if "Publically" not in failReason:
                                failReason = failReason + "Publically accessible CloudTrail bucket discovered."
                except Exception as e:
                    result = False
                    if "AccessDenied" in str(e):
                        offenders.append(str(o['TrailARN']) + ":AccessDenied")
                        if "Missing" not in failReason:
                            failReason = "Missing permissions to verify bucket ACL. " + failReason
                    elif "NoSuchBucket" in str(e):
                        offenders.append(str(o['TrailARN']) + ":NoBucket")
                        if "Trailbucket" not in failReason:
                            failReason = "Trailbucket doesn't exist. " + failReason
                    else:
                        offenders.append(str(o['TrailARN']) + ":CannotVerify")
                        if "Cannot" not in failReason:
                            failReason = "Cannot verify bucket ACL. " + failReason
            else:
                result = False
                offenders.append(str(o['TrailARN']) + "NoS3Logging")
                failReason = "Cloudtrail not configured to log to S3. " + failReason
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 2.4 Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)
def ensure_cloudtrail_cloudwatch_logs_integration(cloudtrails):
    """Summary
    Args:
        cloudtrails (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "2.4"
    description = "Ensure CloudTrail trails are integrated with CloudWatch Logs"
    scored = True
    for m, n in cloudtrails.iteritems():
        for o in n:
            try:
                if "arn:aws:logs" in o['CloudWatchLogsLogGroupArn']:
                    pass
                else:
                    result = False
                    failReason = "CloudTrails without CloudWatch Logs discovered"
                    offenders.append(str(o['TrailARN']))
            except:
                result = False
                failReason = "CloudTrails without CloudWatch Logs discovered"
                offenders.append(str(o['TrailARN']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 2.5 Ensure AWS Config is enabled in all regions (Scored)
def ensure_config_all_regions(regions):
    """Summary
    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "2.5"
    description = "Ensure AWS Config is enabled in all regions"
    scored = True
    globalConfigCapture = False  # Only one region needs to capture global events
    for n in regions:
        configClient = boto3.client('config', region_name=n)
        response = configClient.describe_configuration_recorder_status()
        # Get recording status
        try:
            if not response['ConfigurationRecordersStatus'][0]['recording'] is True:
                result = False
                failReason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
                offenders.append(str(n) + ":NotRecording")
        except:
            result = False
            failReason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
            offenders.append(str(n) + ":NotRecording")

        # Verify that each region is capturing all events
        response = configClient.describe_configuration_recorders()
        try:
            if not response['ConfigurationRecorders'][0]['recordingGroup']['allSupported'] is True:
                result = False
                failReason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
                offenders.append(str(n) + ":NotAllEvents")
        except:
            pass  # This indicates that Config is disabled in the region and will be captured above.

        # Check if region is capturing global events. Fail is verified later since only one region needs to capture them.
        try:
            if response['ConfigurationRecorders'][0]['recordingGroup']['includeGlobalResourceTypes'] is True:
                globalConfigCapture = True
        except:
            pass

        # Verify the delivery channels
        response = configClient.describe_delivery_channel_status()
        try:
            if response['DeliveryChannelsStatus'][0]['configHistoryDeliveryInfo']['lastStatus'] != "SUCCESS":
                result = False
                failReason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
                offenders.append(str(n) + ":S3Delivery")
        except:
            pass  # Will be captured by earlier rule
        try:
            if response['DeliveryChannelsStatus'][0]['configStreamDeliveryInfo']['lastStatus'] != "SUCCESS":
                result = False
                failReason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
                offenders.append(str(n) + ":SNSDelivery")
        except:
            pass  # Will be captured by earlier rule

    # Verify that global events is captured by any region
    if globalConfigCapture is False:
        result = False
        failReason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
        offenders.append("Global:NotRecording")
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 2.6 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)
def ensure_cloudtrail_bucket_logging(cloudtrails):
    """Summary
    Args:
        cloudtrails (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "2.6"
    description = "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket"
    scored = True
    for m, n in cloudtrails.iteritems():
        for o in n:
            # it is possible to have a cloudtrail configured with a nonexistant bucket
            try:
                response = S3_CLIENT.get_bucket_logging(Bucket=o['S3BucketName'])
            except:
                result = False
                failReason = "Cloudtrail not configured to log to S3. "
                offenders.append(str(o['TrailARN']))
            try:
                if response['LoggingEnabled']:
                    pass
            except:
                result = False
                failReason = failReason + "CloudTrail S3 bucket without logging discovered"
                offenders.append("Trail:" + str(o['TrailARN']) + " - S3Bucket:" + str(o['S3BucketName']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 2.7 Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)
def ensure_cloudtrail_encryption_kms(cloudtrails):
    """Summary
    Args:
        cloudtrails (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "2.7"
    description = "Ensure CloudTrail logs are encrypted at rest using KMS CMKs"
    scored = True
    for m, n in cloudtrails.iteritems():
        for o in n:
            try:
                if o['KmsKeyId']:
                    pass
            except:
                result = False
                failReason = "CloudTrail not using KMS CMK for encryption discovered"
                offenders.append("Trail:" + str(o['TrailARN']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 2.8 Ensure rotation for customer created CMKs is enabled (Scored)
def ensure_kms_cmk_rotation(regions):
    """Summary
    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "2.8"
    description = "Ensure rotation for customer created CMKs is enabled"
    scored = True
    for n in regions:
        kms_client = boto3.client('kms', region_name=n)
        paginator = kms_client.get_paginator('list_keys')
        response_iterator = paginator.paginate()
        for page in response_iterator:
            for n in page['Keys']:
                try:
                    rotationStatus = kms_client.get_key_rotation_status(KeyId=n['KeyId'])
                    if rotationStatus['KeyRotationEnabled'] is False:
                        keyDescription = kms_client.describe_key(KeyId=n['KeyId'])
                        if "Default master key that protects my" not in str(keyDescription['KeyMetadata']['Description']):  # Ignore service keys
                            result = False
                            failReason = "KMS CMK rotation not enabled"
                            offenders.append("Key:" + str(keyDescription['KeyMetadata']['Arn']))
                except:
                    pass  # Ignore keys without permission, for example ACM key
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

    region_list = get_regions()
    cred_report = get_cred_report()
    password_policy = get_account_password_policy()
    cloud_trails = get_cloudtrails(region_list)
    accountNumber = get_account_number()

    control2 = []
    control2.append(ensure_cloud_trail_all_regions(cloud_trails))
    control2.append(ensure_cloudtrail_validation(cloud_trails))
    control2.append(ensure_cloudtrail_bucket_not_public(cloud_trails))
    control2.append(ensure_cloudtrail_cloudwatch_logs_integration(cloud_trails))
    control2.append(ensure_config_all_regions(region_list))
    control2.append(ensure_cloudtrail_bucket_logging(cloud_trails))
    control2.append(ensure_cloudtrail_encryption_kms(cloud_trails))
    control2.append(ensure_kms_cmk_rotation(region_list))

    controls = []
    controls.append(control2)

    if SCRIPT_OUTPUT_JSON:
        json_output(controls)

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

    if not profile_name == "":
        try:
            boto3.setup_default_session(profile_name=profile_name)
            IAM_CLIENT = boto3.client('iam')
            S3_CLIENT = boto3.client('s3')
        except Exception as e:
            if "could not be found" in str(e):
                print("Error: " + str(e))
                print("Please verify your profile name.")
                sys.exit(2)

    try:
        client = boto3.client('ec2')
    except Exception as e:
        if "You must specify a region" in str(e):
            if profile_name == "":
                boto3.setup_default_session(region_name='us-east-1')
            else:
                boto3.setup_default_session(profile_name=profile_name, region_name='us-east-1')
lambda_handler("test", "test")
