var async = require('async');
var AWS = require('aws-sdk');

function getPluginInfo() {
	return {
		title: 'Access Keys',
		query: 'accessKeys',
		category: 'IAM',
		description: 'Ensures access keys are properly rotated and audited',
		tests: {
			accessKeysRotated: {
				title: 'Access Keys Rotated',
				description: 'Ensures access keys are not older than 180 days in order to reduce accidental exposures',
				more_info: 'Access keys should be rotated frequently to avoid having them accidentally exposed.',
				link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html',
				recommended_action: 'To rotate an access key, first create a new key, replace the key and secret throughout your app or scripts, then set the previous key to disabled. Once you ensure that no services are broken, then fully delete the old key.',
				results: []
			},
			accessKeysLastUsed: {
				title: 'Access Keys Last Used',
				description: 'Detects access keys that have not been used for a period of time and that should be decomissioned',
				more_info: 'Having numerous, unused access keys extends the attack surface. Access keys should be removed if they are no longer being used.',
				link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html',
				recommended_action: 'Log into the IAM portal and remove the offending access key.',
				results: []
			},
			accessKeysExtra: {
				title: 'Access Keys Extra',
				description: 'Detects the use of more than one access key by any single user',
				more_info: 'Having more than one access key for a single user increases the chance of accidental exposure. Each account should only have one key that defines the users permissions.',
				link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html',
				recommended_action: 'Remove the extra access key for the specified user.',
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
				var returnMsg = {
					status: 3,
					message: 'Unable to query for users',
					region: 'global'
				};
				pluginInfo.tests.accessKeysRotated.results.push(returnMsg);
				pluginInfo.tests.accessKeysLastUsed.results.push(returnMsg);
				pluginInfo.tests.accessKeysExtra.results.push(returnMsg);

				return callback(null, pluginInfo);
			}

			if (data && data.Users) {
				if (data.Users.length) {
					var good = [];
					var bad = [];

					if (data.Users.length > 100) {
						var returnMsg = {
							status: 3,
							message: 'Unable to query for more than 100 user access keys',
							region: 'global'
						};
						pluginInfo.tests.accessKeysRotated.results.push(returnMsg);
						pluginInfo.tests.accessKeysLastUsed.results.push(returnMsg);

						data.Users = data.Users.slice(0,100);
					}

					var allAccessKeys = [];

					var oneDay = 24*60*60*1000;
					var now = new Date();
					var oneEightyDaysAgo = new Date(now - (oneDay*180));
					var threeSixtyDaysAgo = new Date(now - (oneDay*360));

					async.eachLimit(data.Users, 20, function(user, cb){
						iam.listAccessKeys({UserName: user.UserName}, function(accessKeyErr, accessKeyData){
							if (accessKeyErr) {
								pluginInfo.tests.accessKeysRotated.results.push({
									status: 3,
									message: 'Unable to query access keys for user: ' + user.UserName,
									region: 'global',
									resource: user.Arn
								});
							} else {
								if (accessKeyData && accessKeyData.AccessKeyMetadata) {
									if (accessKeyData.AccessKeyMetadata.length) {
										if (accessKeyData.AccessKeyMetadata.length > 1) {
											pluginInfo.tests.accessKeysExtra.results.push({
												status: 1,
												message: 'User: ' + user.UserName + ' is using ' + accessKeyData.AccessKeyMetadata.length + ' access keys',
												region: 'global',
												resource: user.Arn
											});
										}

										for (i in accessKeyData.AccessKeyMetadata) {
											allAccessKeys.push(accessKeyData.AccessKeyMetadata[i].AccessKeyId);
											
											var keyDate = new Date(accessKeyData.AccessKeyMetadata[i].CreateDate);
											var daysOld = Math.round(Math.abs((now.getTime() - keyDate.getTime())/(oneDay)));

											var message = 'Access key: ' + accessKeyData.AccessKeyMetadata[i].AccessKeyId + ' for user: ' + accessKeyData.AccessKeyMetadata[i].UserName + ' is ' + daysOld + ' days old';
											var status = 0;
											
											if (keyDate < threeSixtyDaysAgo) {
												status = 2;
											} else if (keyDate < oneEightyDaysAgo) {
												status = 1;
											}

											pluginInfo.tests.accessKeysRotated.results.push({
												status: status,
												message: message,
												region: 'global',
												resource: accessKeyData.AccessKeyMetadata[i].AccessKeyId
											});
										}
									}
								}
							}
							cb();
						});
					}, function(err){
						if (err) {
							var errMsg = {
								status: 3,
								message: 'Unable to query access keys',
								region: 'global'
							};
							pluginInfo.tests.accessKeysRotated.results.push(errMsg);
							pluginInfo.tests.accessKeysLastUsed.results.push(errMsg);
							pluginInfo.tests.accessKeysExtra.results.push(errMsg);

							return callback(null, pluginInfo);
						}

						if (!allAccessKeys.length) {
							var returnMsg = {
								status: 0,
								message: 'No access keys found',
								region: 'global'
							};
							pluginInfo.tests.accessKeysRotated.results.push(returnMsg);
							pluginInfo.tests.accessKeysLastUsed.results.push(returnMsg);
							pluginInfo.tests.accessKeysExtra.results.push(returnMsg);

							return callback(null, pluginInfo);
						}

						// Add a PASS result if no users had more than one key
						if (!pluginInfo.tests.accessKeysExtra.results.length) {
							pluginInfo.tests.accessKeysExtra.results.push({
								status: 0,
								message: 'No users had more than 1 access key',
								region: 'global'
							});
						}

						// Now test last used info
						if (allAccessKeys.length > 100) {
							pluginInfo.tests.accessKeysLastUsed.results.push({
								status: 3,
								message: 'Unable to query for more than 100 user access keys',
								region: 'global'
							});

							allAccessKeys = allAccessKeys.slice(0,100);
						}

						async.eachLimit(allAccessKeys, 10, function(accessKey, cb){
							iam.getAccessKeyLastUsed({AccessKeyId: accessKey}, function(accessKeyErr, accessKeyData){
								if (accessKeyErr || !accessKeyData) {
									pluginInfo.tests.accessKeysLastUsed.results.push({
										status: 3,
										message: 'Unable to query last used status for access key: ' + accessKey,
										region: 'global',
										resource: accessKey
									});

									return cb();
								}

								if (!accessKeyData.AccessKeyLastUsed || !accessKeyData.AccessKeyLastUsed.LastUsedDate) {
									pluginInfo.tests.accessKeysLastUsed.results.push({
										status: 0,
										message: 'Access key: ' + accessKey + ' for user: ' + (accessKeyData.UserName || 'unknown') + ' has not been used',
										region: 'global',
										resource: accessKey
									});

									return cb();
								}

								var keyUsedDate = new Date(accessKeyData.AccessKeyLastUsed.LastUsedDate);
								var daysAgo = Math.round(Math.abs((now.getTime() - keyUsedDate.getTime())/(oneDay)));
								var message = 'Access key: ' + accessKey + ' for user: ' + accessKeyData.UserName + ' was last used ' + daysAgo + ' days ago';
								var status = 0;

								if (keyUsedDate < threeSixtyDaysAgo) {
									status = 2;
								} else if (keyUsedDate < oneEightyDaysAgo) {
									status = 1;
								}

								pluginInfo.tests.accessKeysLastUsed.results.push({
									status: status,
									message: message,
									region: 'global',
									resource: accessKey
								});

								cb();
							});
						}, function(err){
							if (err) {
								pluginInfo.tests.accessKeysLastUsed.results.push({
									status: 3,
									message: 'Unable to query access keys',
									region: 'global'
								});
							}

							return callback(null, pluginInfo);
						});
					});
				} else {
					var returnMsg = {
						status: 0,
						message: 'No user accounts with access keys found',
						region: 'global'
					};
					pluginInfo.tests.accessKeysRotated.results.push(returnMsg);
					pluginInfo.tests.accessKeysLastUsed.results.push(returnMsg);

					callback(null, pluginInfo);
				}
			} else {
				var returnMsg = {
					status: 3,
					message: 'Unable to query access keys',
					region: 'global'
				};
				pluginInfo.tests.accessKeysRotated.results.push(returnMsg);
				pluginInfo.tests.accessKeysLastUsed.results.push(returnMsg);
				pluginInfo.tests.accessKeysExtra.results.push(returnMsg);

				return callback(null, pluginInfo);
			}
		});
	}
};