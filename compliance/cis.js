// These rule mappings are based on CIS Amazon Web Services Foundation v1.2.0 - 05-23-2018

var controls = {
    'rootAccountInUse': {
        // TODO Additional audit rules are required, attachment of policies recommendation
        awsid: '1.1',
        profile: 1,
        scored: true,
        title: 'Avoid the use of the "root" account'
    },

    'usersMfaEnabled': {
        // TODO a rule that checked if the system is setup to force IAM User Self-Registration would be good
        awsid: '1.2',
        profile: 1,
        scored: true,
        title: ' Ensure multi-factor authentication (MFA) is enabled for all IAM ' +
                'users that have a console password'
    },

    'usersPasswordLastUsed': {
        awsid: '1.3',
        profile: 1,
        scored: true,
        title: 'Ensure credentials unused for 90 days or greater are disabled'
    },

    'accessKeysLastUsed': {
        awsid: '1.3',
        profile: 1,
        scored: true,
        title: 'Ensure credentials unused for 90 days or greater are disabled'
    },

    'accessKeysRotated': {
        awsid: '1.4',
        profile: 1,
        scored: true,
        title: 'Ensure access keys are rotated every 90 days or less'
    },

    'passwordRequiresUppercase': {
        awsid: '1.5',
        profile: 1,
        scored: true,
        title: 'Ensure IAM password policy requires at least one uppercase letter'
    },

    'passwordRequiresLowercase': {
        awsid: '1.6',
        profile: 1,
        scored: true,
        title: ' Ensure IAM password policy require at least one lowercase letter'
    },

    'passwordRequiresSymbols': {
        awsid: '1.7',
        profile: 1,
        scored: true,
        title: ' Ensure IAM password policy require at least one symbol'
    },

    'passwordRequiresNumbers': {
        awsid: '1.8',
        profile: 1,
        scored: true,
        title: 'Ensure IAM password policy require at least one number'
    },

    'minPasswordLength': {
        awsid: '1.9',
        profile: 1,
        scored: true,
        title: 'Ensure IAM password policy requires minimum length of 14 or greater'
    },

    'passwordReusePrevention': {
        awsid: '1.10',
        profile: 1,
        scored: true,
        title: 'Ensure IAM password policy prevents password reuse'
    },

    'passwordExpiration': {
        awsid: '1.11',
        profile: 1,
        scored: true,
        title: 'Ensure IAM password policy expires passwords within 90 days or less'
    },

    'rootAccessKeys': {
        awsid: '1.12',
        profile: 1,
        scored: true,
        title: 'Ensure no root account access key exists'
    },

    'rootMfaEnabled': {
        awsid: '1.13',
        profile: 1,
        scored: true,
        title: 'Ensure MFA is enabled for the "root" account'
    },

    // 1.14 - TODO Ensure hardware MFA is enabled for the "root" account
    // 1.15 - CANNOT IMPLEMENT? -  Ensure security questions are registered in the AWS account

    'noUserIamPolicies': {
        awsid: '1.16',
        profile: 1,
        scored: true,
        title: 'Ensure IAM policies are attached only to groups or roles'
    },

    // 1.17 - CANNOT IMPLEMENT? - CONTACT INFORMATION IS UP TO DATE
    // 1.18 - CANNOT IMPLEMENT? - SECURITY CONTACT INFORMATION IS REGISTERED
    // 1.19 - CANNOT IMPLEMENT? - INSTANCE-BASED ROLES FOR AWS RESOURCE ACCESS
    // 1.20 - TODO SUPPORT ROLE EXISTS INSTANCE-BASED ROLES FOR AWS RESOURCE ACCESS
    // 1.21 - TODO ACCESS KEYS ARE ACTUALLY USED
    // 1.22 - TODO NO USER POLICY WITH *:*

    'cloudtrailEnabled': {
        awsid: '2.1',
        profile: 1,
        scored: true,
        title: 'Ensure CloudTrail is enabled in all regions'
    },

    'cloudtrailFileValidation': {
        awsid: '2.2',
        profile: 2,
        scored: true,
        title: 'Ensure CloudTrail log file validation is enabled'
    },

    'cloudtrailBucketPrivate': {
        awsid: '2.3',
        profile: 1,
        scored: true,
        title: 'Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible'
    },

    'cloudtrailToCloudwatch': {
        awsid: '2.4',
        profile: 1,
        scored: true,
        title: 'Ensure CloudTrail trails are integrated with CloudWatch Logs'
    },

    'configServiceEnabled': {
        awsid: '2.5',
        profile: 1,
        scored: true,
        title: ' Ensure AWS Config is enabled in all regions'
    },

    'cloudtrailBucketAccessLogging': {
        awsid: '2.6',
        profile: 1,
        scored: true,
        title: ' Ensure AWS Config is enabled in all regions'
    },

    'cloudtrailEncryption' : {
        awsid: '2.7',
        profile: 2,
        scored: true,
        title: 'Ensure CloudTrail logs are encrypted at rest using KMS CMKs'
    },

    'kmsKeyRotation': {
        awsid: '2.8',
        profile: 2,
        scored: true,
        title: 'Ensure rotation for customer created CMKs is enabled'
    },

    'flowLogsEnabled': {
        awsid: '2.8',
        profile: 2,
        scored: true,
        title: 'Ensure VPC flow logging is enabled in all VPCs'
    },

    
    'monitoringMetrics': {
        awsid: '3',
        profile: 1,
        scored: true,
        title: 'Monitoring'
    },
    
    'openSSH': {
        awsid: '4.1',
        profile: 1,
        scored: true,
        title: 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 22'
    },

    'openRDP': {
        awsid: '4.2',
        profile: 1,
        scored: true,
        title: 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389'
    },

    'defaultSecurityGroup': {
        awsid: '4.3',
        profile: 2,
        scored: true,
        title: 'Ensure the default security group of every VPC restricts all traffic'
    }

    // 4.4 Ensure routing tables for VPC peering are "least access"
}

var maxProfileLevel = -1

// Defines a way of filtering plugins for those plugins that are related to
// PCI controls. The PCI information is defined inline, so this compliance
// checks for that information on the plugin.
module.exports = {
    describe: function(pluginId, plugin) {
        return controls[pluginId].title
    },

    includes: function (pluginId, plugin) {
        return maxProfileLevel <= 0 ? controls.hasOwnProperty(pluginId) : (controls.hasOwnProperty(pluginId) && controls[pluginId].profile <= maxProfileLevel)
    },

    setMaxProfile: function (level) {
        maxProfileLevel = level
    }
}