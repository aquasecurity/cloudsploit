var async = require('async');
var AWS = require('aws-sdk');

function getPluginInfo() {
	return {
		title: 'Users MFA Enabled',
		query: 'usersMfaEnabled',
		category: 'IAM',
		description: 'Ensures a multi-factor authentication device is enabled for all users within the account',
		tests: {
			usersMfaEnabled: {
				title: 'Users MFA Enabled',
				description: 'Ensures a multi-factor authentication device is enabled for all users within the account',
				more_info: 'User accounts should have an MFA device setup to enable two-factor authentication',
				link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
				recommended_action: 'Enable an MFA device for the user account',
				results: []
			}
		}
	};
}

module.exports = {
	title: getPluginInfo().title,
	query: getPluginInfo().query,
	category: getPluginInfo().category,
	description: getPluginInfo().description,
	more_info: getPluginInfo().more_info,
	link: getPluginInfo().link,
	tests: getPluginInfo().tests,

	run: function(AWSConfig, callback) {

		var iam = new AWS.IAM(AWSConfig);
		var pluginInfo = getPluginInfo();

		iam.listUsers({}, function(err, data){
			if (err) {
				pluginInfo.tests.usersMfaEnabled.results.push({
					status: 3,
					message: 'Unable to query for user MFA status',
					region: 'global'
				});

				return callback(null, pluginInfo);
			}

			// Perform checks for establishing if MFA token is enabled
			if (data && data.Users) {
				if (data.Users.length) {
					var good = [];
					var bad = [];

					if (data.Users.length > 100) {
						pluginInfo.tests.usersMfaEnabled.results.push({
							status: 3,
							message: 'Unable to query for more than 100 users MFA status',
							region: 'global'
						});

						data.Users = data.Users.slice(0,100);
					}

					async.eachLimit(data.Users, 3, function(user, cb){
						if (!user.PasswordLastUsed) {
							// Skip users without passwords since they won't be logging into the console
							return cb();
						}
						iam.listMFADevices({UserName: user.UserName}, function(mfaErr, mfaData){
							if (mfaErr) {
								pluginInfo.tests.usersMfaEnabled.results.push({
									status: 3,
									message: 'Unable to query MFA device for user: ' + user.UserName,
									region: 'global'
								});
							} else {
								if (mfaData && mfaData.MFADevices) {
									if (mfaData.MFADevices.length) {
										pluginInfo.tests.usersMfaEnabled.results.push({
											status: 0,
											message: 'User: ' + user.UserName + ' has an MFA device',
											region: 'global'
										});
									} else {
										pluginInfo.tests.usersMfaEnabled.results.push({
											status: 1,
											message: 'User: ' + user.UserName + ' does not have an MFA device enabled',
											region: 'global'
										});
									}
								}
							}
							cb();
						});
					}, function(err){
						if (err) {
							pluginInfo.tests.usersMfaEnabled.results.push({
								status: 3,
								message: 'Unable to query for user MFA status',
								region: 'global'
							});
						}
						callback(null, pluginInfo);
					});
				} else {
					pluginInfo.tests.usersMfaEnabled.results.push({
						status: 0,
						message: 'No user accounts found',
						region: 'global'
					});
					callback(null, pluginInfo);
				}
			} else {
				pluginInfo.tests.usersMfaEnabled.results.push({
					status: 3,
					message: 'Unable to query for user MFA status',
					region: 'global'
				});

				return callback(null, pluginInfo);
			}
		});
	}
};