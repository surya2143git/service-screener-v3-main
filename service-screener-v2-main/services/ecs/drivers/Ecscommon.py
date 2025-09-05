import boto3
import botocore
from utils.Config import Config
from utils.Policy import Policy
from services.Evaluator import Evaluator


class EcsCommon(Evaluator):
    OUTBOUNDSGMINIMALRULES = {
        "tcp": [
            80,
            443,
        ],  # Example minimal ports for ECS; adjust based on needs (e.g., HTTP/HTTPS)
        "udp": [],
    }

    def __init__(self, ecsCluster, clusterInfo, ecsClient, ec2Client, iamClient):
        super().__init__()
        self.cluster = ecsCluster
        self.clusterInfo = clusterInfo
        self.ecsClient = ecsClient
        self.ec2Client = ec2Client
        self.iamClient = iamClient
        self._resourceName = ecsCluster

        self.init()

    # ECS doesn't have direct cluster versions like EKS; this is a placeholder or adapt to check container instance AMIs
    def getNewerVersionCnt(self, versionList, clusterVersion):
        newerVersionCnt = 0
        for version in versionList:
            if clusterVersion < version:
                newerVersionCnt += 1

        return newerVersionCnt

    def getVersions(self):
        # Placeholder: ECS doesn't have addon versions; perhaps fetch available ECS-optimized AMI versions or skip
        versionList = Config.get("ECSVersionList", False)

        if versionList is False:
            # Example: Hardcode or fetch ECS versions; this is illustrative
            versionList = ["1.0", "1.1", "1.2"]  # Replace with actual logic if needed
            uniqVersionList = sorted(set(versionList), reverse=True)
            Config.set("ECSVersionList", uniqVersionList)
            return uniqVersionList
        else:
            return versionList

    def getLatestVersion(self, versionList):
        return versionList[0]

    def _checkClusterVersion(self):
        # ECS clusters don't have a 'version' field; adapt to check something else, e.g., container instances
        clusterVersion = (
            "1.0"  # Placeholder; fetch from clusterInfo or container instances
        )

        versionList = self.getVersions()
        newVersionCnt = self.getNewerVersionCnt(versionList, clusterVersion)
        latestVersion = self.getLatestVersion(versionList)

        if newVersionCnt >= 3:
            self.results["ecsClusterVersionEol"] = [
                -1,
                "Current: " + clusterVersion + ", Latest: " + latestVersion,
            ]
        elif newVersionCnt > 0 and newVersionCnt < 3:
            self.results["ecsClusterVersionUpdate"] = [
                -1,
                "Current: " + clusterVersion + ", Latest: " + latestVersion,
            ]

        return

    def clusterSGInboundRuleCheck(self, rule, sgID, accountId):
        if len(rule.get("UserIdGroupPairs")) == 0:
            ## No SG Group found means the source is not from self SG, Flagged
            return False
        else:
            ## Check if the only self SG assigned into the rules
            for group in rule.get("UserIdGroupPairs"):
                if group.get("GroupId") != sgID or group.get("UserId") != accountId:
                    return False

        return True

    def clusterSGOutboundRuleCheck(self, rule, sgID, accountId):
        minimalPort = self.OUTBOUNDSGMINIMALRULES

        if len(rule.get("UserIdGroupPairs")) == 0:
            return False
        else:
            ## ECS Cluster SG Outbound minimal requirement is listed in the minimal port
            if rule.get("IpProtocol") in list(minimalPort.keys()) and rule.get(
                "FromPort"
            ) in minimalPort.get(rule.get("IpProtocol")):
                ## Check if the only self SG assigned into the rules
                for group in rule.get("UserIdGroupPairs"):
                    if group.get("GroupId") != sgID or group.get("UserId") != accountId:
                        return False
            else:
                return False

        return True

    def _checkClusterSecurityGroup(self):
        stsInfo = Config.get("stsInfo", False)
        if stsInfo is False:
            print("Unable to get Account ID, skipped Cluster Security Group check")
            return

        # ECS clusters don't have a direct 'clusterSecurityGroupId'; adapt to fetch from container instances or services
        # Example: List container instances and get their security groups
        containerInstances = self.ecsClient.list_container_instances(
            cluster=self.cluster
        )
        if not containerInstances.get("containerInstanceArns"):
            print(
                "No container instances found for cluster "
                + self.cluster
                + ". Skipped Security Group check"
            )
            return

        # For simplicity, assume we fetch SG from first instance; in real, loop through all
        instanceDesc = self.ecsClient.describe_container_instances(
            cluster=self.cluster,
            containerInstances=containerInstances["containerInstanceArns"][:1],
        )
        ec2InstanceId = instanceDesc["containerInstances"][0]["ec2InstanceId"]
        ec2Desc = self.ec2Client.describe_instances(InstanceIds=[ec2InstanceId])
        sgID = ec2Desc["Reservations"][0]["Instances"][0]["SecurityGroups"][0][
            "GroupId"
        ]

        if sgID is None:
            print(
                "Cluster security group not found for cluster "
                + self.cluster
                + ". skipped Cluster Security Group check"
            )
            return

        accountId = Config.get("stsInfo", False).get("Account")

        response = self.ec2Client.describe_security_groups(GroupIds=[sgID])
        sgInfos = response.get("SecurityGroups")

        for info in sgInfos:
            ## Inbound Rule Checking
            inboundRules = info.get("IpPermissions")
            for rule in inboundRules:
                result = self.clusterSGInboundRuleCheck(rule, sgID, accountId)
                if not result:
                    self.results["ecsClusterSGRestriction"] = [-1, sgID]
                    return

            ## Outbound Rule Checking
            outboundRules = info.get("IpPermissionsEgress")

            for rule in outboundRules:
                result = self.clusterSGOutboundRuleCheck(rule, sgID, accountId)
                if not result:
                    self.results["ecsClusterSGRestriction"] = [-1, sgID]
                    return

        return

    def _checkPublicClusterEndpoint(self):
        # ECS doesn't have direct 'endpointPublicAccess'; perhaps check if services have public IPs
        # Placeholder: Assume checking settings or tasks
        if "public" in self.clusterInfo.get("settings", []):  # Illustrative
            self.results["ecsEndpointPublicAccess"] = [-1, "Enabled"]

        return

    def _checkEnvelopeEncryption(self):
        # ECS uses secrets in task definitions; check if encryption is enabled (e.g., via KMS)
        # Placeholder: ECS clusters don't have 'encryptionConfig'; check services/tasks
        if self.clusterInfo.get("encryptionConfig") is None:  # Adapt as needed
            self.results["ecsSecretsEncryption"] = [-1, "Disabled"]

        return

    def _checkClusterLogging(self):
        # Check if logging is enabled for the cluster's services/tasks
        # Example: List services and check log configurations
        services = self.ecsClient.list_services(cluster=self.cluster)
        for serviceArn in services.get("serviceArns", [])[
            :1
        ]:  # Check first for example
            serviceDesc = self.ecsClient.describe_services(
                cluster=self.cluster, services=[serviceArn]
            )
            logConfig = serviceDesc["services"][0].get("logConfiguration")
            if logConfig is None or not logConfig.get("logDriver"):
                self.results["ecsClusterLogging"] = [-1, "Disabled"]
                return

        return

    def inlinePolicyLeastPrivilege(self, roleName):
        response = self.iamClient.list_role_policies(RoleName=roleName)

        for policyName in response.get("PolicyNames"):
            policyResp = self.iamClient.get_role_policy(
                RoleName=roleName, PolicyName=policyName
            )
            document = policyResp.get("PolicyDocument")

            pObj = Policy(document)
            pObj.inspectAccess()
            if pObj.hasFullAccessToOneResource() or pObj.hasFullAccessAdmin():
                return False

        return True

    def attachedPolicyLeastPrivilege(self, roleName):
        response = self.iamClient.list_attached_role_policies(RoleName=roleName)

        for policy in response.get("AttachedPolicies"):
            policyInfoResp = self.iamClient.get_policy(
                PolicyArn=policy.get("PolicyArn")
            )

            policyInfo = policyInfoResp.get("Policy")
            if len(policyInfo) == 0:
                print(
                    "Skipped. Unable to retrieve policy information for "
                    + policy.get("PolicyArn")
                )
                continue

            policyArn = policyInfo.get("Arn")
            policyVersion = policyInfo.get("DefaultVersionId")

            policyResp = self.iamClient.get_policy_version(
                PolicyArn=policyArn, VersionId=policyVersion
            )

            if len(policyResp.get("PolicyVersion")) == 0:
                print(
                    "Skipped. Unable to retrieve policy permission for "
                    + policy.get("PolicyArn")
                    + " version "
                    + policyVersion
                )
                continue

            document = policyResp.get("PolicyVersion").get("Document")

            pObj = Policy(document)
            pObj.inspectAccess()
            if pObj.hasFullAccessToOneResource() or pObj.hasFullAccessAdmin():
                return False

        return True

    def _checkRoleLeastPrivilege(self):
        # ECS clusters may have service roles; adapt from clusterInfo
        roleArn = self.clusterInfo.get(
            "roleArn"
        )  # If available; otherwise fetch from services
        if not roleArn:
            print("No role found for cluster " + self.cluster)
            return
        roleName = roleArn.split("role/", 1)[1]

        result = self.inlinePolicyLeastPrivilege(roleName)
        if result is False:
            self.results["ecsClusterRoleLeastPrivilege"] = [-1, roleName]
            return

        result = self.attachedPolicyLeastPrivilege(roleName)
        if result is False:
            self.results["ecsClusterRoleLeastPrivilege"] = [-1, roleName]
            return

        return
