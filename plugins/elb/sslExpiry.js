// TODO: Finish

var async = require('async');

var pluginInfo = {
	title: 'SSL Certificate Expiry',
	query: 'sslExpiry',
	category: 'ELB',
	aws_service: 'ELB',
	description: 'Detect upcoming expiration of SSL certs used with ELBs',
	more_info: 'SSL certificates that have expired will trigger warnings in all major browsers',
	link: 'http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-update-ssl-cert.html',
	tests: {
		sslExpiry: {
			title: 'SSL Certificate Expiry',
			description: 'Detect upcoming expiration of SSL certs used with ELBs',
			recommendedAction: 'Update your SSL certificate before the expiration date',
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
		var elb = new AWS.ELB();

		elb.describeLoadBalancers({}, function(elbErr, elbData) {
			if (elbErr) {
				return callback(elbErr);
			}

			if (elbData && elbData.LoadBalancerDescriptions) {
				console.log(JSON.stringify(elbData,null,2));
				var certs = [];
				for (i in elbData.LoadBalancerDescriptions) {
					if (elbData)
					for (j in elbData.LoadBalancerDescriptions[i].)
				}
			} else {
				pluginInfo.tests.sslExpiry.push({
					status: 0,
					message: 'No load balancers to check for certificates'
				});
				callback(null, pluginInfo);
			}
		});

		// iam.getServerCertificate({}, function(err, data){
		// 	if (err) {
		// 		callback(err);
		// 		return;
		// 	}

		// 	console.log(data);

		// 	// Perform checks for establishing if MFA token is enabled
		// 	if (data && data.trailList) {
		// 		if (!data.trailList.length) {
		// 			pluginInfo.tests.cloudtrailEnabled.results.push({
		// 				status: 0,
		// 				message: 'No S3 buckets to check'
		// 			});
		// 			callback(null, pluginInfo);
		// 		} else {
		// 			var s3 = new AWS.S3();

		// 			async.eachLimit(data.trailList, 2, function(trailList, cb){
		// 				s3.getBucketVersioning({Bucket:trailList.S3BucketName}, function(s3err, s3data){
		// 					if (s3data && s3data.MFADelete && s3data.MFADelete === 'Enabled') {
		// 						pluginInfo.tests.cloudtrailEnabled.results.push({
		// 							status: 0,
		// 							message: 'Bucket: ' + trailList.S3BucketName + ' has MFA delete enabled'
		// 						});
		// 					} else {
		// 						pluginInfo.tests.cloudtrailEnabled.results.push({
		// 							status: 1,
		// 							message: 'Bucket: ' + trailList.S3BucketName + ' has MFA delete disabled'
		// 						});
		// 					}
		// 					cb();
		// 				});
		// 			}, function(err){
		// 				callback(null, pluginInfo);
		// 			});
		// 		}
		// 	} else {
		// 		callback('unexpected return data');
		// 		return;
		// 	}
		// });
	}
};