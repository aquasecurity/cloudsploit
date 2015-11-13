// Export all available scans

module.exports = {
	'cloudtrailBucketDelete': require('./plugins/cloudtrail/cloudtrailBucketDelete.js'),
	'cloudtrailEnabled': require('./plugins/cloudtrail/cloudtrailEnabled.js'),

	'accountLimits': require('./plugins/ec2/accountLimits.js'),
	'securityGroups': require('./plugins/ec2/securityGroups.js'),

	'certificateExpiry': require('./plugins/ec2/certificateExpiry.js'),
	'insecureCiphers': require('./plugins/ec2/insecureCiphers.js'),

	'passwordPolicy': require('./plugins/iam/passwordPolicy.js'),
	'rootAccountSecurity': require('./plugins/iam/rootAccountSecurity.js'),
	'usersMfaEnabled': require('./plugins/iam/usersMfaEnabled.js'),
	'accessKeys': require('./plugins/iam/accessKeys.js'),
	'groupSecurity': require('./plugins/iam/groupSecurity.js'),
	
	'detectClassic': require('./plugins/vpc/detectClassic.js'),

	's3Buckets': require('./plugins/s3/s3Buckets.js'),

	'domainSecurity': require('./plugins/route53/domainSecurity.js'),

	'databaseSecurity': require('./plugins/rds/databaseSecurity.js')
};