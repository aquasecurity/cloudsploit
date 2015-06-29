var async = require('async');

module.exports = {
	title: 'SSLv3',
	query: 'sslV3',
	description: 'Ensures SSLv3 is disabled on applicable load balancers',

	run: function(AWS, callback) {

		var elb = new AWS.ELB();

		elb.describeLoadBalancers(function(err, data){
			if (err) {
				callback(err);
				return;
			}

			if (data) {
				// Loop through data and collect LB names and policies
				var paramArray = [];
				for (i in data.LoadBalancerDescriptions) {
					var lb = data.LoadBalancerDescriptions[i];

					for (i in lb.ListenerDescriptions) {
						var lbld = lb.ListenerDescriptions[i];
						if (lbld.Listener.Protocol = 'HTTPS' && lbld.PolicyNames.length > 0) {
							var params = {
								LoadBalancerName: lb.LoadBalancerName,
								PolicyNames: [
									lbld.PolicyNames[0]
								]
							}
							paramArray.push(params);
						}
					}
				}

				// Now make queries for each LB
				var good = [];
				var bad = [];
				async.eachSeries(paramArray, function(param, done){
					elb.describeLoadBalancerPolicies(param, function(err, data){
						if(err) {
							console.log(err);
							done();
						} else {
							for (i in data.PolicyDescriptions[0].PolicyAttributeDescriptions) {
								if (data.PolicyDescriptions[0].PolicyAttributeDescriptions[i].AttributeName == 'Protocol-SSLv3') {
									if (data.PolicyDescriptions[0].PolicyAttributeDescriptions[i].AttributeValue == 'true') {
										//console.log('WARNING: ' + param.LoadBalancerName + ' supports SSLv3');
										bad.push(param.LoadBalancerName);
									} else {
										//console.log('OK: ' + param.LoadBalancerName + ' does not support SSLv3');
										good.push(param.LoadBalancerName);
									}
								}
							}
							done();
						}
					});
				}, function(err){
					if (err) {
						callback('error executing check');
					} else {
						if (bad.length == 0 && good.length > 0) {
							callback(null, {
								status: 'pass',
								description: 'All load balancers avoid using SSLv3: ' + good.join(', ')
							});
						} else if (bad.length == 0 && good.length == 0) {
							callback(null, {
								status: 'pass',
								description: 'No load balancers utilize SSL termination. Nothing to check.'
							});
						} else if (bad.length > 0 && bad.length < good.length) {
							callback(null, {
								status: 'warn',
								description: 'Some load balancers support SSLv3: ' + bad.join(', ')
							});
						} else if (bad.length > 0 && bad.length > good.length) {
							callback(null, {
								status: 'fail',
								description: 'More than 50% of load balancers support SSLv3: ' + bad.join(', ')
							});
						} else {
							callback(null, {
								status: 'fail',
								description: 'Some load balancers support SSLv3: ' + bad.join(', ')
							});
						}
					}
				});
			} else {
				callback('unexpected return data');
				return;
			}
		});
	}
};