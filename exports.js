// Export all available scans

module.exports = {
	'cloudtrailBucketDelete'	: require(__dirname + '/plugins/cloudtrail/cloudtrailBucketDelete.js'),
	'cloudtrailEnabled'			: require(__dirname + '/plugins/cloudtrail/cloudtrailEnabled.js'),
	'cloudtrailFileValidation'	: require(__dirname + '/plugins/cloudtrail/cloudtrailFileValidation.js'),
	'cloudtrailToCloudwatch'	: require(__dirname + '/plugins/cloudtrail/cloudtrailToCloudwatch.js'),

	'elasticIpLimit'			: require(__dirname + '/plugins/ec2/elasticIpLimit.js'),
	'excessiveSecurityGroups'	: require(__dirname + '/plugins/ec2/excessiveSecurityGroups.js'),
	'insecureCiphers'			: require(__dirname + '/plugins/ec2/insecureCiphers.js'),
	'instanceLimit'				: require(__dirname + '/plugins/ec2/instanceLimit.js'),
	'openCIFS'					: require(__dirname + '/plugins/ec2/openCIFS.js'),
	'openDNS'					: require(__dirname + '/plugins/ec2/openDNS.js'),
	'openFTP'					: require(__dirname + '/plugins/ec2/openFTP.js'),
	'openMySQL'					: require(__dirname + '/plugins/ec2/openMySQL.js'),
	'openNetBIOS'				: require(__dirname + '/plugins/ec2/openNetBIOS.js'),
	'openPostgreSQL'			: require(__dirname + '/plugins/ec2/openPostgreSQL.js'),
	'openRDP'					: require(__dirname + '/plugins/ec2/openRDP.js'),
	'openRPC'					: require(__dirname + '/plugins/ec2/openRPC.js'),
	'openSMBoTCP'				: require(__dirname + '/plugins/ec2/openSMBoTCP.js'),
	'openSMTP'					: require(__dirname + '/plugins/ec2/openSMTP.js'),
	'openSQLServer'				: require(__dirname + '/plugins/ec2/openSQLServer.js'),
	'openSSH'					: require(__dirname + '/plugins/ec2/openSSH.js'),
	'openTelnet'				: require(__dirname + '/plugins/ec2/openTelnet.js'),
	'openVNCClient'				: require(__dirname + '/plugins/ec2/openVNCClient.js'),
	'openVNCServer'				: require(__dirname + '/plugins/ec2/openVNCServer.js'),
	'vpcElasticIpLimit'			: require(__dirname + '/plugins/ec2/vpcElasticIpLimit.js'),

	'accessKeysExtra'			: require(__dirname + '/plugins/iam/accessKeysExtra.js'),
	'accessKeysLastUsed'		: require(__dirname + '/plugins/iam/accessKeysLastUsed.js'),
	'accessKeysRotated'			: require(__dirname + '/plugins/iam/accessKeysRotated.js'),
	'certificateExpiry'			: require(__dirname + '/plugins/iam/certificateExpiry.js'),
	'emptyGroups'				: require(__dirname + '/plugins/iam/emptyGroups.js'),
	'maxPasswordAge'			: require(__dirname + '/plugins/iam/maxPasswordAge.js'),
	'minPasswordLength'			: require(__dirname + '/plugins/iam/minPasswordLength.js'),
	'noUserIamPolicies'			: require(__dirname + '/plugins/iam/noUserIamPolicies.js'),
	'passwordExpiration'		: require(__dirname + '/plugins/iam/passwordExpiration.js'),
	'passwordRequiresLowercase'	: require(__dirname + '/plugins/iam/passwordRequiresLowercase.js'),
	'passwordRequiresNumbers'	: require(__dirname + '/plugins/iam/passwordRequiresNumbers.js'),
	'passwordRequiresSymbols'	: require(__dirname + '/plugins/iam/passwordRequiresSymbols.js'),
	'passwordRequiresUppercase'	: require(__dirname + '/plugins/iam/passwordRequiresUppercase.js'),
	'passwordReusePrevention'	: require(__dirname + '/plugins/iam/passwordReusePrevention.js'),
	'rootAccessKeys'			: require(__dirname + '/plugins/iam/rootAccessKeys.js'),
	'rootAccountInUse'			: require(__dirname + '/plugins/iam/rootAccountInUse.js'),
	'rootMfaEnabled'			: require(__dirname + '/plugins/iam/rootMfaEnabled.js'),
	'sshKeysRotated'			: require(__dirname + '/plugins/iam/sshKeysRotated.js'),
	'usersMfaEnabled'			: require(__dirname + '/plugins/iam/usersMfaEnabled.js'),

	'kmsKeyRotation'			: require(__dirname + '/plugins/kms/kmsKeyRotation.js'),

	'rdsAutomatedBackups'		: require(__dirname + '/plugins/rds/rdsAutomatedBackups.js'),
	'rdsEncryptionEnabled'		: require(__dirname + '/plugins/rds/rdsEncryptionEnabled.js'),
	'rdsPubliclyAccessible'		: require(__dirname + '/plugins/rds/rdsPubliclyAccessible.js'),
	'rdsRestorable'				: require(__dirname + '/plugins/rds/rdsRestorable.js'),

	'domainAutoRenew'			: require(__dirname + '/plugins/route53/domainAutoRenew.js'),
	'domainExpiry'				: require(__dirname + '/plugins/route53/domainExpiry.js'),
	'domainTransferLock'		: require(__dirname + '/plugins/route53/domainTransferLock.js'),

	'bucketAllUsersPolicy'		: require(__dirname + '/plugins/s3/bucketAllUsersPolicy.js'),

	'classicInstances'			: require(__dirname + '/plugins/vpc/classicInstances.js')	
};