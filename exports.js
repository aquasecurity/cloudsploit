// Export all available scans

module.exports = {
	'cloudtrailBucketDelete': require(__dirname + '/plugins/cloudtrail/cloudtrailBucketDelete.js'),
	'cloudtrailEnabled': require(__dirname + '/plugins/cloudtrail/cloudtrailEnabled.js'),

	'accountLimits': require(__dirname + '/plugins/ec2/accountLimits.js'),
	'securityGroups': require(__dirname + '/plugins/ec2/securityGroups.js'),

	'certificateExpiry': require(__dirname + '/plugins/ec2/certificateExpiry.js'),
	'insecureCiphers': require(__dirname + '/plugins/ec2/insecureCiphers.js'),

	'passwordPolicy': require(__dirname + '/plugins/iam/passwordPolicy.js'),
	'rootAccountSecurity': require(__dirname + '/plugins/iam/rootAccountSecurity.js'),
	'usersMfaEnabled': require(__dirname + '/plugins/iam/usersMfaEnabled.js'),
	'accessKeys': require(__dirname + '/plugins/iam/accessKeys.js'),
	
	'detectClassic': require(__dirname + '/plugins/vpc/detectClassic.js')
};