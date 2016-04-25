var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Access Keys Rotated',
	category: 'IAM',
	description: 'Ensures access keys are not older than 180 days in order to reduce accidental exposures',
	more_info: 'Access keys should be rotated frequently to avoid having them accidentally exposed.',
	link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html',
	recommended_action: 'To rotate an access key, first create a new key, replace the key and secret throughout your app or scripts, then set the previous key to disabled. Once you ensure that no services are broken, then fully delete the old key.',

	run: function(AWSConfig, callback) {

		var results = [];

		var iam = new AWS.IAM(AWSConfig);

		helpers.functions.waitForCredentialReport(iam, function(err, data){
			if (err || !data || !data.Content) {
				results.push({
					status: 3,
					message: 'Unable to query for users',
					region: 'global'
				});

				return callback(null, results);
			}

			try {
				var csvContent = data.Content.toString();
				var csvRows = csvContent.split('\n');
			} catch(e) {
				results.push({
					status: 3,
					message: 'Unable to query for users',
					region: 'global'
				});

				return callback(null, results);
			}

			console.log(csvContent);
			
			user,
			arn,
			user_creation_time,
			password_enabled,
			password_last_used,
			password_last_changed,
			password_next_rotation,
			mfa_active,
			access_key_1_active,
			access_key_1_last_rotated,
			access_key_1_last_used_date,
			access_key_1_last_used_region,
			access_key_1_last_used_service,
			access_key_2_active,
			access_key_2_last_rotated,
			access_key_2_last_used_date,
			access_key_2_last_used_region,
			access_key_2_last_used_service,
			cert_1_active,
			cert_1_last_rotated,
			cert_2_active,cert_2_last_rotated

			cloudsploit-self,
			arn:aws:iam::057012691312:user/cloudsploit-self,
			2015-07-12T19:47:22+00:00,
			false,
			N/A,
			N/A,
			N/A,
			false,
			true,
			2015-07-12T19:47:22+00:00,
			2015-08-31T04:58:00+00:00,
			us-west-2,
			ec2,
			true,
			2015-08-18T03:23:05+00:00,
			2016-04-24T21:23:00+00:00,
			eu-central-1,
			ec2,
			false,
			N/A,
			false,
			N/A

			for (r in csvRows) {
				var csvRow = csvRows[r];
				var csvFields = csvRow.split(',');

				var user = csvFields[0];
				var arn = csvFields[1];
				var userCreationTime = csvFields[2];
				var accessKey1Active = csvFields[8];
				var accessKey1LastRotated = csvFields[9];
				var accessKey2Active = csvFields[13];
				var accessKey2LastRotated = csvFields[14];

				if (accessKey1Active === 'true' && )

				if (helpers.functions.daysAgo(userCreationTime) < 90) {
					results.push({
						status: 0,
						message: 'User created less than 90 days ago',
						region: 'global',
						resource: arn
					});

					return callback(null, results);
				}

				if (csvFields[0] === '<root_account>') {
					var rootCreated = new Date(csvFields[2]);
					var rootLastUsed = new Date(csvFields[4]);

					// If the account was accessed >7 days after being created and
					// <10 days ago, then assume the root account is being actively used
					if (helpers.functions.daysBetween(rootCreated, rootLastUsed) > 7 &&
						helpers.functions.daysAgo(rootLastUsed) < 10) {
						console.log('Used recently');
					}

				}
			}
		});

		// iam.listUsers({}, function(err, data){
		// 	if (err) {
		// 		var returnMsg = {
		// 			status: 3,
		// 			message: 'Unable to query for users',
		// 			region: 'global'
		// 		};
		// 		pluginInfo.tests.accessKeysRotated.results.push(returnMsg);
		// 		pluginInfo.tests.accessKeysLastUsed.results.push(returnMsg);
		// 		pluginInfo.tests.accessKeysExtra.results.push(returnMsg);

		// 		return callback(null, pluginInfo);
		// 	}

		// 	if (data && data.Users) {
		// 		if (data.Users.length) {
		// 			var good = [];
		// 			var bad = [];

		// 			var allAccessKeys = [];

		// 			var oneDay = 24*60*60*1000;
		// 			var now = new Date();
		// 			var oneEightyDaysAgo = new Date(now - (oneDay*180));
		// 			var threeSixtyDaysAgo = new Date(now - (oneDay*360));

		// 			async.eachLimit(data.Users, 20, function(user, cb){
		// 				iam.listAccessKeys({UserName: user.UserName}, function(accessKeyErr, accessKeyData){
		// 					if (accessKeyErr) {
		// 						pluginInfo.tests.accessKeysRotated.results.push({
		// 							status: 3,
		// 							message: 'Unable to query access keys for user: ' + user.UserName,
		// 							region: 'global',
		// 							resource: user.Arn
		// 						});
		// 					} else {
		// 						if (accessKeyData && accessKeyData.AccessKeyMetadata) {
		// 							if (accessKeyData.AccessKeyMetadata.length) {
		// 								if (accessKeyData.AccessKeyMetadata.length > 1) {
		// 									pluginInfo.tests.accessKeysExtra.results.push({
		// 										status: 1,
		// 										message: 'User: ' + user.UserName + ' is using ' + accessKeyData.AccessKeyMetadata.length + ' access keys',
		// 										region: 'global',
		// 										resource: user.Arn
		// 									});
		// 								}

		// 								for (i in accessKeyData.AccessKeyMetadata) {
		// 									allAccessKeys.push(accessKeyData.AccessKeyMetadata[i].AccessKeyId);
											
		// 									var keyDate = new Date(accessKeyData.AccessKeyMetadata[i].CreateDate);
		// 									var daysOld = Math.round(Math.abs((now.getTime() - keyDate.getTime())/(oneDay)));

		// 									var message = 'Access key: ' + accessKeyData.AccessKeyMetadata[i].AccessKeyId + ' for user: ' + accessKeyData.AccessKeyMetadata[i].UserName + ' is ' + daysOld + ' days old';
		// 									var status = 0;
											
		// 									if (keyDate < threeSixtyDaysAgo) {
		// 										status = 2;
		// 									} else if (keyDate < oneEightyDaysAgo) {
		// 										status = 1;
		// 									}

		// 									pluginInfo.tests.accessKeysRotated.results.push({
		// 										status: status,
		// 										message: message,
		// 										region: 'global',
		// 										resource: accessKeyData.AccessKeyMetadata[i].AccessKeyId
		// 									});
		// 								}
		// 							}
		// 						}
		// 					}
		// 					cb();
		// 				});
		// 			}, function(err){
		// 				if (err) {
		// 					var errMsg = {
		// 						status: 3,
		// 						message: 'Unable to query access keys',
		// 						region: 'global'
		// 					};
		// 					pluginInfo.tests.accessKeysRotated.results.push(errMsg);
		// 					pluginInfo.tests.accessKeysLastUsed.results.push(errMsg);
		// 					pluginInfo.tests.accessKeysExtra.results.push(errMsg);

		// 					return callback(null, pluginInfo);
		// 				}

		// 				if (!allAccessKeys.length) {
		// 					var returnMsg = {
		// 						status: 0,
		// 						message: 'No access keys found',
		// 						region: 'global'
		// 					};
		// 					pluginInfo.tests.accessKeysRotated.results.push(returnMsg);
		// 					pluginInfo.tests.accessKeysLastUsed.results.push(returnMsg);
		// 					pluginInfo.tests.accessKeysExtra.results.push(returnMsg);

		// 					return callback(null, pluginInfo);
		// 				}

		// 				// Add a PASS result if no users had more than one key
		// 				if (!pluginInfo.tests.accessKeysExtra.results.length) {
		// 					pluginInfo.tests.accessKeysExtra.results.push({
		// 						status: 0,
		// 						message: 'No users had more than 1 access key',
		// 						region: 'global'
		// 					});
		// 				}

		// 				async.eachLimit(allAccessKeys, 10, function(accessKey, cb){
		// 					iam.getAccessKeyLastUsed({AccessKeyId: accessKey}, function(accessKeyErr, accessKeyData){
		// 						if (accessKeyErr || !accessKeyData) {
		// 							pluginInfo.tests.accessKeysLastUsed.results.push({
		// 								status: 3,
		// 								message: 'Unable to query last used status for access key: ' + accessKey,
		// 								region: 'global',
		// 								resource: accessKey
		// 							});

		// 							return cb();
		// 						}

		// 						if (!accessKeyData.AccessKeyLastUsed || !accessKeyData.AccessKeyLastUsed.LastUsedDate) {
		// 							pluginInfo.tests.accessKeysLastUsed.results.push({
		// 								status: 0,
		// 								message: 'Access key: ' + accessKey + ' for user: ' + (accessKeyData.UserName || 'unknown') + ' has not been used',
		// 								region: 'global',
		// 								resource: accessKey
		// 							});

		// 							return cb();
		// 						}

		// 						var keyUsedDate = new Date(accessKeyData.AccessKeyLastUsed.LastUsedDate);
		// 						var daysAgo = Math.round(Math.abs((now.getTime() - keyUsedDate.getTime())/(oneDay)));
		// 						var message = 'Access key: ' + accessKey + ' for user: ' + accessKeyData.UserName + ' was last used ' + daysAgo + ' days ago';
		// 						var status = 0;

		// 						if (keyUsedDate < threeSixtyDaysAgo) {
		// 							status = 2;
		// 						} else if (keyUsedDate < oneEightyDaysAgo) {
		// 							status = 1;
		// 						}

		// 						pluginInfo.tests.accessKeysLastUsed.results.push({
		// 							status: status,
		// 							message: message,
		// 							region: 'global',
		// 							resource: accessKey
		// 						});

		// 						cb();
		// 					});
		// 				}, function(err){
		// 					if (err) {
		// 						pluginInfo.tests.accessKeysLastUsed.results.push({
		// 							status: 3,
		// 							message: 'Unable to query access keys',
		// 							region: 'global'
		// 						});
		// 					}

		// 					return callback(null, pluginInfo);
		// 				});
		// 			});
		// 		} else {
		// 			var returnMsg = {
		// 				status: 0,
		// 				message: 'No user accounts with access keys found',
		// 				region: 'global'
		// 			};
		// 			pluginInfo.tests.accessKeysRotated.results.push(returnMsg);
		// 			pluginInfo.tests.accessKeysLastUsed.results.push(returnMsg);

		// 			callback(null, pluginInfo);
		// 		}
		// 	} else {
		// 		var returnMsg = {
		// 			status: 3,
		// 			message: 'Unable to query access keys',
		// 			region: 'global'
		// 		};
		// 		pluginInfo.tests.accessKeysRotated.results.push(returnMsg);
		// 		pluginInfo.tests.accessKeysLastUsed.results.push(returnMsg);
		// 		pluginInfo.tests.accessKeysExtra.results.push(returnMsg);

		// 		return callback(null, pluginInfo);
		// 	}
		// });
	}
};