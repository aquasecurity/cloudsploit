// Export all available scans

module.exports = {
    'asgMultiAz'                       : require(__dirname + '/plugins/autoscaling/asgMultiAz.js'),

    'publicS3Origin'                : require(__dirname + '/plugins/cloudfront/publicS3Origin.js'),
    'secureOrigin'                  : require(__dirname + '/plugins/cloudfront/secureOrigin.js'),
    'insecureProtocols'             : require(__dirname + '/plugins/cloudfront/insecureProtocols.js'),
    'cloudfrontHttpsOnly'           : require(__dirname + '/plugins/cloudfront/cloudfrontHttpsOnly.js'),
    'cloudtrailBucketAccessLogging' : require(__dirname + '/plugins/cloudtrail/cloudtrailBucketAccessLogging.js'),
    'cloudtrailBucketDelete'        : require(__dirname + '/plugins/cloudtrail/cloudtrailBucketDelete.js'),
    'cloudtrailEnabled'             : require(__dirname + '/plugins/cloudtrail/cloudtrailEnabled.js'),
    'cloudtrailEncryption'          : require(__dirname + '/plugins/cloudtrail/cloudtrailEncryption.js'),
    'cloudtrailFileValidation'      : require(__dirname + '/plugins/cloudtrail/cloudtrailFileValidation.js'),
    'cloudtrailToCloudwatch'        : require(__dirname + '/plugins/cloudtrail/cloudtrailToCloudwatch.js'),
    'cloudtrailBucketPrivate'       : require(__dirname + '/plugins/cloudtrail/cloudtrailBucketPrivate.js'),

    'configServiceEnabled'          : require(__dirname + '/plugins/configservice/configServiceEnabled.js'),

    'defaultSecurityGroup'          : require(__dirname + '/plugins/ec2/defaultSecurityGroup.js'),
    'elasticIpLimit'                : require(__dirname + '/plugins/ec2/elasticIpLimit.js'),
    'excessiveSecurityGroups'       : require(__dirname + '/plugins/ec2/excessiveSecurityGroups.js'),
    'instanceLimit'                 : require(__dirname + '/plugins/ec2/instanceLimit.js'),
    'openCIFS'                      : require(__dirname + '/plugins/ec2/openCIFS.js'),
    'openDNS'                       : require(__dirname + '/plugins/ec2/openDNS.js'),
    'openFTP'                       : require(__dirname + '/plugins/ec2/openFTP.js'),
    'openMySQL'                     : require(__dirname + '/plugins/ec2/openMySQL.js'),
    'openNetBIOS'                   : require(__dirname + '/plugins/ec2/openNetBIOS.js'),
    'openPostgreSQL'                : require(__dirname + '/plugins/ec2/openPostgreSQL.js'),
    'openRDP'                       : require(__dirname + '/plugins/ec2/openRDP.js'),
    'openRPC'                       : require(__dirname + '/plugins/ec2/openRPC.js'),
    'openSMBoTCP'                   : require(__dirname + '/plugins/ec2/openSMBoTCP.js'),
    'openSMTP'                      : require(__dirname + '/plugins/ec2/openSMTP.js'),
    'openSQLServer'                 : require(__dirname + '/plugins/ec2/openSQLServer.js'),
    'openSSH'                       : require(__dirname + '/plugins/ec2/openSSH.js'),
    'openTelnet'                    : require(__dirname + '/plugins/ec2/openTelnet.js'),
    'openVNCClient'                 : require(__dirname + '/plugins/ec2/openVNCClient.js'),
    'openVNCServer'                 : require(__dirname + '/plugins/ec2/openVNCServer.js'),
    'vpcElasticIpLimit'             : require(__dirname + '/plugins/ec2/vpcElasticIpLimit.js'),
    'classicInstances'              : require(__dirname + '/plugins/ec2/classicInstances.js'),
    'flowLogsEnabled'               : require(__dirname + '/plugins/ec2/flowLogsEnabled.js'),
    'vpcMultipleSubnets'            : require(__dirname + '/plugins/ec2/multipleSubnets.js'),
    'publicAmi'                     : require(__dirname + '/plugins/ec2/publicAmi.js'),
    'encryptedAmi'                  : require(__dirname + '/plugins/ec2/encryptedAmi.js'),
    'instanceIamRole'               : require(__dirname + '/plugins/ec2/instanceIamRole.js'),

    'insecureCiphers'               : require(__dirname + '/plugins/elb/insecureCiphers.js'),
    'elbHttpsOnly'                  : require(__dirname + '/plugins/elb/elbHttpsOnly.js'),
    'elbLoggingEnabled'             : require(__dirname + '/plugins/elb/elbLoggingEnabled.js'),

    'accessKeysExtra'               : require(__dirname + '/plugins/iam/accessKeysExtra.js'),
    'accessKeysLastUsed'            : require(__dirname + '/plugins/iam/accessKeysLastUsed.js'),
    'accessKeysRotated'             : require(__dirname + '/plugins/iam/accessKeysRotated.js'),
    'certificateExpiry'             : require(__dirname + '/plugins/iam/certificateExpiry.js'),
    'emptyGroups'                   : require(__dirname + '/plugins/iam/emptyGroups.js'),
    'maxPasswordAge'                : require(__dirname + '/plugins/iam/maxPasswordAge.js'),
    'minPasswordLength'             : require(__dirname + '/plugins/iam/minPasswordLength.js'),
    'noUserIamPolicies'             : require(__dirname + '/plugins/iam/noUserIamPolicies.js'),
    'passwordExpiration'            : require(__dirname + '/plugins/iam/passwordExpiration.js'),
    'passwordRequiresLowercase'     : require(__dirname + '/plugins/iam/passwordRequiresLowercase.js'),
    'passwordRequiresNumbers'       : require(__dirname + '/plugins/iam/passwordRequiresNumbers.js'),
    'passwordRequiresSymbols'       : require(__dirname + '/plugins/iam/passwordRequiresSymbols.js'),
    'passwordRequiresUppercase'     : require(__dirname + '/plugins/iam/passwordRequiresUppercase.js'),
    'passwordReusePrevention'       : require(__dirname + '/plugins/iam/passwordReusePrevention.js'),
    'rootAccessKeys'                : require(__dirname + '/plugins/iam/rootAccessKeys.js'),
    'rootAccountInUse'              : require(__dirname + '/plugins/iam/rootAccountInUse.js'),
    'rootMfaEnabled'                : require(__dirname + '/plugins/iam/rootMfaEnabled.js'),
    'sshKeysRotated'                : require(__dirname + '/plugins/iam/sshKeysRotated.js'),
    'usersMfaEnabled'               : require(__dirname + '/plugins/iam/usersMfaEnabled.js'),

    'kmsKeyRotation'                : require(__dirname + '/plugins/kms/kmsKeyRotation.js'),

    'rdsAutomatedBackups'           : require(__dirname + '/plugins/rds/rdsAutomatedBackups.js'),
    'rdsEncryptionEnabled'          : require(__dirname + '/plugins/rds/rdsEncryptionEnabled.js'),
    'rdsPubliclyAccessible'         : require(__dirname + '/plugins/rds/rdsPubliclyAccessible.js'),
    'rdsRestorable'                 : require(__dirname + '/plugins/rds/rdsRestorable.js'),
    'rdsMultiAz'                    : require(__dirname + '/plugins/rds/rdsMultiAz.js'),

    'domainAutoRenew'               : require(__dirname + '/plugins/route53/domainAutoRenew.js'),
    'domainExpiry'                  : require(__dirname + '/plugins/route53/domainExpiry.js'),
    'domainTransferLock'            : require(__dirname + '/plugins/route53/domainTransferLock.js'),

    'bucketAllUsersPolicy'          : require(__dirname + '/plugins/s3/bucketAllUsersPolicy.js'),

    'dkimEnabled'                   : require(__dirname + '/plugins/ses/dkimEnabled.js'),

    'topicPolicies'                 : require(__dirname + '/plugins/sns/topicPolicies.js'),
  
    'lambdaOldRuntimes'             : require(__dirname + '/plugins/lambda/lambdaOldRuntimes.js'),
  
    'monitoringMetrics'             : require(__dirname + '/plugins/cloudwatchlogs/monitoringMetrics.js'),

    'redshiftEncryptionEnabled'     : require(__dirname + '/plugins/redshift/redshiftEncryptionEnabled.js'),
    'redshiftPubliclyAccessible'    : require(__dirname + '/plugins/redshift/redshiftPubliclyAccessible.js')
};
