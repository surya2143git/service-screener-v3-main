# Service Screener

An open source guidance tool for the AWS environment. Click [here](https://dev.d11el1twchxpia.amplifyapp.com/index.html) for sample report.

***Important note***: *The generated report has to be hosted locally and MUST NOT be internet accessible*

This version of Service Screener may not compatible with the Greater China region. Our community folks have made it work [here](https://github.com/lijh-aws-tools/service-screener-cn). 

## Overview
Service Screener is a tool that runs automated checks on AWS environments and provides recommendations based on AWS and community best practices. 

AWS customers can use this tool on their own environments and use the recommendations to improve the Security, Reliability, Operational Excellence, Performance Efficiency and Cost Optimisation at the service level. 

This tool aims to complement the [AWS Well Architected Tool](https://aws.amazon.com/well-architected-tool/). 

## How does it work?
Service Screener uses [AWS CloudShell](https://aws.amazon.com/cloudshell/), a free service that provides a browser-based shell to run scripts using the AWS CLI. It runs multiple `describe` and `get` API calls to determine the configuration of your environment.

## How much does it cost?
Running this tool is free as it is covered under the AWS Free Tier. If you have exceeded the free tier limits, each run will cost less than $0.01.

## Prerequisites
1. Please review the [DISCLAIMER](./DISCLAIMER.md) before proceeding. 
2. You must have an existing AWS Account.
3. You must have an IAM User with sufficient read permissions. Here is a sample [policy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/ReadOnlyAccess.html). Additionally, the IAM User must also have the following permissions:
   - AWSCloudShellFullAccess
   - cloudformation:CreateStack
   - cloudformation:DeleteStack

4. (Optional) If you need to run cross-account operations, additional permissions are required:
   - iam:SetSecurityTokenServicePreferences

## Installing service-screener V2
1. [Log in to your AWS account](https://docs.aws.amazon.com/cloudshell/latest/userguide/getting-started.html#start-session) using the IAM User with sufficient permissions described above. 
2. Launch [AWS CloudShell](https://docs.aws.amazon.com/cloudshell/latest/userguide/getting-started.html#launch-region-shell) in any region. 
3. In the AWS CloudShell terminal, run this script this to install the dependencies:
   ``` bash
   cd /tmp
   python3 -m venv .
   source bin/activate
   python3 -m pip install --upgrade pip
   rm -rf service-screener-v2
   git clone https://github.com/aws-samples/service-screener-v2.git
   cd service-screener-v2
   pip install -r requirements.txt
   python3 unzip_botocore_lambda_runtime.py
   alias screener='python3 $(pwd)/main.py'
   ```

## Using Service Screener
When running Service Screener, you will need to specify the regions and services you would like it to run on. For the full list of services currently supported, please see "SERVICES_IDENTIFIER_MAPPING" in [Config.py](./utils/Config.py).

We recommend running it in all regions where you have workloads deployed in. Adjust the commands below to suit your needs then copy and paste it into CloudShell to run Service Screener. 

**Example 1: (Recommended) Run in the Singapore region, check all services with beta features enabled**
``` bash
screener --regions ap-southeast-1 --beta 1
``` 

**Example 1a: Run in the Singapore region, check all services on stable releases**
``` bash
screener --regions ap-southeast-1
```

**Example 2: Run in the Singapore region, check only Amazon S3**
``` bash
screener --regions ap-southeast-1 --services s3
```

**Example 3: Run in the Singapore & North Virginia regions, check all services**
``` bash
screener --regions ap-southeast-1,us-east-1
```

**Example 4: Run in the Singapore & North Virginia regions, check RDS and IAM**
``` bash
screener --regions ap-southeast-1,us-east-1 --services rds,iam
```

**Example 5: Run in the Singapore region, filter resources based on tags (e.g: Name=env Values=prod and Name=department Values=hr,coe)**
``` bash
screener --regions ap-southeast-1 --tags env=prod%department=hr,coe
```

**Example 6: Run in all regions and all services**
``` bash
screener --regions ALL
```

**Example 7: Run with suppression file to ignore specific findings**
``` bash
screener --regions us-east-1 --services s3 --suppress_file ./suppressions.json
```

## Other parameters

### Suppression File
To suppress specific findings, create a JSON file with the suppressions and use the `--suppress-file` parameter:

```json
{
 "metadata": {
   "version": "1.0",
   "description": "Your suppression description"
 },
 "suppressions": [
   {
     "service": "s3",
     "rule": "BucketReplication"
   },
   {
     "service": "s3",
     "rule": "BucketVersioning",
     "resource_id": ["Bucket::my-bucket-name"]
   }
 ]
}
```

For more details, see the [suppressions documentation](./docs/Suppressions.md).

### Migration Evaluation ID
For AWS Partners conducting migration evaluations:
```json
{
    "mpe": {
        "id": "aaaa-1111-cccc"
    }
}
```

Usage:

``` bash
screener --regions ap-southeast-1 --others '{"mpe": {"id": "aaaa-1111-cccc"}}'
```

### Well-Architected Tool Integration
To create a workload and milestone in the Well-Architected Tool:
``` json
{
    "WA": {
        "region": "ap-southeast-1",
        "reportName": "SS_Report",
        "newMileStone": 1
    }
}
```

Parameters:

- `region`: The region where the Well-Architected workload will be created
- `reportName`: Name of the workload (use existing name to update)
- `newMileStone`:
   - Set to 1 to create a new milestone each time (Recommended)
   - Set to 0 to create a milestone only if none exists

Usage:

``` bash
screener --regions ap-southeast-1 --beta 1 --others '{"WA": {"region": "ap-southeast-1", "reportName": "SS_Report", "newMileStone": 1}}'
```

### Combining Parameters
You can combine both MPE and WA parameters:

``` json
{
    "WA": {
        "region": "ap-southeast-1",
        "reportName": "SS_Report",
        "newMileStone": 1
    },
    "mpe": {
        "id": "aaaa-1111-cccc"
    }
}
```

Usage:

``` bash
screener --regions ap-southeast-1 --others '{"WA": {"region": "ap-southeast-1", "reportName": "SS_Report", "newMileStone": 1}, "mpe": {"id": "aaaa-1111-cccc"}}'
```

## Downloading the report
The output is generated as a ~/service-screener-v2/output.zip file. 
You can [download the file](https://docs.aws.amazon.com/cloudshell/latest/userguide/working-with-cloudshell.html#files-storage) in the CloudShell console by clicking the *Download file* button under the *Actions* menu on the top right of the CloudShell console. 

Once downloaded, unzip the file and open 'index.html' in your browser. You should see a page like [this](https://dev.d11el1twchxpia.amplifyapp.com/961319563195/index.html).

Ensure that you can see the service(s) run on listed on the left pane.
You can navigate to the service(s) listed to see detailed findings on each service. 


## Using the report 
The report provides you an easy-to-navigate dashboard of the various best-practice checks that were run. 

Use the left navigation bar to explore the checks for each service. Expand each check to read the description, find out which resources were highlighted, and get recommendations on how to remediate the findings.  

Besides the HTML report, you can also find two JSON files that record the findings in each AWS account's folder:

- `api-raw.json`: Contains the raw findings
- `api-full.json`: Contains the full results in JSON format

## Contributing to service-screener
We encourage public contributions! Please review [CONTRIBUTING](./CONTRIBUTING.md) for details on our code of conduct and development process.

## Development Guide
A comprehensive development guide is available at [Development Guide](./docs/DevelopmentGuide.md).

## Contact
Please review [CONTRIBUTING](./CONTRIBUTING.md) to raise any issues. 

## Security
See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License
This project is licensed under the Apache-2.0 License.

