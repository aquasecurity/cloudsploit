var async = require('async');

var pluginInfo = {
	title: 'Users MFA Enabled',
	query: 'usersMfaEnabled',
	category: 'IAM',
	aws_service: 'IAM',
	description: 'Ensures a multi-factor authentication device is enabled for all users within the account',
	more_info: 'User accounts should have an MFA device setup to enable two-factor authentication',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
	tests: {
		usersMfaEnabled: {
			title: 'Users MFA Enabled',
			description: 'Ensures a multi-factor authentication device is enabled for all users within the account',
			recommendedAction: 'Enable an MFA device for the user account',
			results: []
		}
	}
};

module.exports = {
	title: pluginInfo.title,
	query: pluginInfo.query,
	category: pluginInfo.category,
	description: pluginInfo.description,
	more_info: pluginInfo.more_info,
	link: pluginInfo.link,

	run: function(AWS, callback) {

		var iam = new AWS.IAM();

		iam.listUsers({}, function(err, data){
			if (err) {
				callback(err);
				return;
			}

			// Perform checks for establishing if MFA token is enabled
			if (data && data.Users) {
				if (data.Users.length) {
					var good = [];
					var bad = [];

					async.eachLimit(data.Users, 3, function(user, cb){
						iam.listMFADevices({UserName: user.UserName}, function(mfaErr, mfaData){
							if (mfaErr) {
								pluginInfo.tests.usersMfaEnabled.results.push({
									status: 3,
									message: 'Unable to query MFA device for user: ' + user.UserName
								});
							} else {
								if (mfaData && mfaData.MFADevices) {
									if (mfaData.MFADevices.length) {
										pluginInfo.tests.usersMfaEnabled.results.push({
											status: 0,
											message: 'User: ' + user.UserName + ' has an MFA device'
										});
									} else {
										pluginInfo.tests.usersMfaEnabled.results.push({
											status: 1,
											message: 'User: ' + user.UserName + ' does not have an MFA device enabled'
										});
									}
								}
							}
							cb();
						});
					}, function(err){
						if (err) {
							return callback('Error querying for MFA device status');
						}
						callback(null, pluginInfo);
					});
				} else {
					pluginInfo.tests.usersMfaEnabled.results.push({
						status: 0,
						message: 'No user accounts found'
					});
					callback(null, pluginInfo);
				}
			} else {
				callback('unexpected return data');
				return;
			}
		});
	}
};