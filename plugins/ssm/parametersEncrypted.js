var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'SSM Encrypted Parameters',
	category: 'SSM',
	description: 'Ensures SSM Parameters are encrypted',
	more_info: 'SSM Parameters should be encrypted',
	link: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-about.html#sysman-paramstore-securestring',
	recommended_action: 'Recreate unencrypted SSM Parameters with "Type" set to "SecureString"',
	apis: ['SSM:describeParameters'],
	compliance: {
		hipaa: 'HIPAA requires that all data is encrypted, including data at rest'
	},

	run: function(cache, settings, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.ssm, function(region, rcb){
			var describeParameters = helpers.addSource(cache, source,
				['ssm', 'describeParameters', region]);

			if (!describeParameters) return rcb();

			if (describeParameters.err || !describeParameters.data) {
				helpers.addResult(results, 3,
					'Unable to query for SSM Parameters: ' + helpers.addError(describeParameters), region);
				return rcb();
			}

			if (!describeParameters.data.length) {
				helpers.addResult(results, 0, 'No SSM Parameters present', region);
				return rcb();
			}

      var nonSecureStrings = []

      for( i in describeParameters.data) {
        if(describeParameters.data[i].Type != "SecureString"){
          nonSecureStrings.push(describeParameters.data[i].Name);
        }
      }

      if (nonSecureStrings.length > 0) {
				helpers.addResult,(results, 2, 'Non-SecureString SSM Parameters present', region);
				return rcb();
      } else if (nonSecureStrings.length == 0) {
				helpers.addResult(results, 0, 'All SSM Parameters of Type SecureString', region);
				return rcb();
      }

			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
