var AWS = require('aws-sdk');

module.exports = function(AWSConfig, collection, callback) {
	var ses = new AWS.SES(AWSConfig);

	ses.getIdentityDkimAttributes({Identities: collection.ses.listIdentities[AWSConfig.region].data}, function(err, data){
		if (err) {
			collection.ses.getIdentityDkimAttributes[AWSConfig.region].err = err;
		}

		collection.ses.getIdentityDkimAttributes[AWSConfig.region].data = data;

		callback();
	});
};