var async = require('async');

module.exports = {
	title: 'S3 Bucket ACLs',
	query: 's3BucketAcls',
	description: 'Ensures S3 buckets do not have full-control policies for everyone',

	run: function(AWS, callback) {

		var s3 = new AWS.S3();

		s3.listBuckets(function(err, data){
			if (err) {
				callback(err);
				return;
			}

			if (data) {
				if (!data.Buckets || !data.Buckets.length) {
					return callback(null, {
						status: 'pass',
						description: 'This account does not have S3 buckets (or they are not visible to this access key'
					});
				}

				// Loop through data and collect S3 bucket names and policies
				var good = [];
				var bad = [];

				async.each(data.Buckets, function(bucket, callback){
					console.log(bucket);

					s3.getBucketAcl({Bucket: bucket.Name}, function(err, data){
						console.log('policies');
						console.log(err);
						console.log(data);
						callback();
					});
				}, function(err){
					console.log(err);
				});

				
				
				// async.eachSeries(paramArray, function(param, done){
				// 	elb.describeLoadBalancerPolicies(param, function(err, data){
				// 		if(err) {
				// 			console.log(err);
				// 			done();
				// 		} else {
				// 			for (i in data.PolicyDescriptions[0].PolicyAttributeDescriptions) {
				// 				if (data.PolicyDescriptions[0].PolicyAttributeDescriptions[i].AttributeName == 'Protocol-SSLv3') {
				// 					if (data.PolicyDescriptions[0].PolicyAttributeDescriptions[i].AttributeValue == 'true') {
				// 						//console.log('WARNING: ' + param.LoadBalancerName + ' supports SSLv3');
				// 						bad.push(param.LoadBalancerName);
				// 					} else {
				// 						//console.log('OK: ' + param.LoadBalancerName + ' does not support SSLv3');
				// 						good.push(param.LoadBalancerName);
				// 					}
				// 				}
				// 			}
				// 			done();
				// 		}
				// 	});
				// }, function(err){
				// 	if (err) {
				// 		callback('error executing check');
				// 	} else {
				// 		if (bad.length == 0 && good.length > 0) {
				// 			callback(null, {
				// 				status: 'pass',
				// 				description: 'All load balancers avoid using SSLv3: ' + good.join(', ')
				// 			});
				// 		} else if (bad.length == 0 && good.length == 0) {
				// 			callback(null, {
				// 				status: 'pass',
				// 				description: 'No load balancers utilize SSL termination. Nothing to check.'
				// 			});
				// 		} else if (bad.length > 0 && bad.length < good.length) {
				// 			callback(null, {
				// 				status: 'warn',
				// 				description: 'Some load balancers support SSLv3: ' + bad.join(', ')
				// 			});
				// 		} else if (bad.length > 0 && bad.length > good.length) {
				// 			callback(null, {
				// 				status: 'fail',
				// 				description: 'More than 50% of load balancers support SSLv3: ' + bad.join(', ')
				// 			});
				// 		} else {
				// 			callback(null, {
				// 				status: 'fail',
				// 				description: 'Some load balancers support SSLv3: ' + bad.join(', ')
				// 			});
				// 		}
				// 	}
				// });
			} else {
				callback('unexpected return data');
				return;
			}
		});
	}
};