var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
	var iam = new AWS.IAM(AWSConfig);

	var Marker;
	async.doWhilst(function(pageCb) {
		iam.listRoles({
			Marker
		}, function(err, data) {
			if(err) {
				collection.iam.listRoles[AWSCONFIG.region].err = err;
			}

			if (!collection.iam.listRoles[AWSConfig.region].data) collection.iam.listRoles[AWSConfig.region].data = [];
			collection.iam.listRoles[AWSConfig.region].data = collection.iam.listRoles[AWSConfig.region].data.concat(data.Roles);
			Marker = data.Marker;
			pageCb();
		});
	}, function() { return Marker !== undefined }, callback);
};