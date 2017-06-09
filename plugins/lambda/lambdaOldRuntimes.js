var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Lambda Old Runtimes',
	category: 'Lambda',
	description: 'Ensures Lambda functions are not using out-of-date runtime environments.',
	more_info: 'Lambda runtimes should be kept current with recent versions of the underlying codebase. Node.js 0.10.0 should not be used.',
	link: 'http://docs.aws.amazon.com/lambda/latest/dg/current-supported-versions.html',
	recommended_action: 'Upgrade the Lambda function runtime to use a more current version.',
	apis: ['Lambda:listFunctions'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.lambda, function(region, rcb){
			var listFunctions = helpers.addSource(cache, source,
				['lambda', 'listFunctions', region]);

			if (!listFunctions) return rcb();

			if (listFunctions.err || !listFunctions.data) {
				helpers.addResult(results, 3,
					'Unable to query for Lambda functions: ' + helpers.addError(listFunctions), region);
				return rcb();
			}

			if (!listFunctions.data.length) {
				helpers.addResult(results, 0, 'No Lambda functions found', region);
				return rcb();
			}

			var found = false;

			for (f in listFunctions.data) {
				// For resource, attempt to use the endpoint address (more specific) but fallback to the instance identifier
				var lambdaFunction = listFunctions.data[f];

				if (!lambdaFunction.Runtime) continue;

				if (lambdaFunction.Runtime === 'nodejs') {
					found = true;

					helpers.addResult(results, 2,
						'Function is using out-of-date runtime: nodejs',
						region, lambdaFunction.FunctionArn);
				}
			}

			if (!found) {
				helpers.addResult(results, 0,
					'No functions using out-of-date runtimes',
					region);
			}
			
			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
