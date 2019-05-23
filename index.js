#!/usr/bin/env node

var async = require('async');
var fs        	= require("fs");
var plugins = require('./exports.js');
var complianceControls = require('./compliance/controls.js')
var suppress = require('./postprocess/suppress.js')
var output = require('./postprocess/output.js')

var AWSConfig;
var AzureConfig;
var GitHubConfig;
var OracleConfig;

// OPTION 1: Configure service provider credentials through hard-coded config objects

// AWSConfig = {
// 	accessKeyId: '',
// 	secretAccessKey: '',
// 	sessionToken: '',
// 	region: 'us-east-1'
// };

// AzureConfig = {
// 	ApplicationID: '',          // A.K.A ClientID
// 	KeyValue: '',               // Secret
// 	DirectoryID: '',            // A.K.A TenantID or Domain
// 	SubscriptionID: '',
// 	location: 'East US'
// };

// GitHubConfig = {
// 	token: '',						// GitHub app token
// 	url: 'https://api.github.com',	// BaseURL if not using public GitHub
// 	organization: false,			// Set to true if the login is an organization
//  login: ''						// The login id for the user or organization
// };

// Oracle Important Note:
// Please read Oracle API's key generation instructions: config/_oracle/keys/Readme.md
// You will want an API signing key to fill the keyFingerprint and privateKey params
// OracleConfig = {
// 	RESTversion: '/20160918',
// 	tenancyId: 'ocid1.tenancy.oc1..',
// 	compartmentId: 'ocid1.compartment.oc1..',
// 	userId: 'ocid1.user.oc1..',
// 	keyFingerprint: 'YOURKEYFINGERPRINT',
// 	privateKey: fs.readFileSync(__dirname + '/config/_oracle/keys/YOURKEYNAME.pem', 'ascii'),
// 	region: 'us-ashburn-1',
// };

// OPTION 2: Import a service provider config file containing credentials

// AWSConfig = require(__dirname + '/aws_credentials.json');
// AzureConfig = require(__dirname + '/azure_credentials.json');
// GitHubConfig = require(__dirname + '/github_credentials.json');
// OracleConfig = require(__dirname + '/oracle_credentials.json');

// OPTION 3: ENV configuration with service provider env vars
if(process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY){
    AWSConfig = {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey:  process.env.AWS_SECRET_ACCESS_KEY,
        sessionToken: process.env.AWS_SESSION_TOKEN,
        region: process.env.AWS_DEFAULT_REGION || 'us-east-1'
    };
}

if(process.env.AZURE_APPLICATION_ID && process.env.AZURE_KEY_VALUE){
	AzureConfig = {
		ApplicationID: process.env.AZURE_APPLICATION_ID,
		KeyValue:  process.env.AZURE_KEY_VALUE,
		DirectoryID: process.env.AZURE_DIRECTORY_ID,
		SubscriptionID: process.env.AZURE_SUBSCRIPTION_ID,
		region: process.env.AZURE_LOCATION || 'eastus'
	};
}

if(process.env.GITHUB_LOGIN){
	GitHubConfig = {
		url: process.env.GITHUB_URL || 'https://api.github.com',
		login: process.env.GITHUB_LOGIN,
		organization: process.env.GITHUB_ORG ? true : false
	};
}

if(process.env.ORACLE_TENANCY_ID && process.env.ORACLE_USER_ID){
	OracleConfig = {
		RESTversion: process.env.ORACLE_REST_VERSION,
		tenancyId: process.env.ORACLE_TENANCY_ID,
		compartmentId: process.env.ORACLE_COMPARTMENT_ID,
		userId:  process.env.ORACLE_USER_ID,
		keyFingerprint: process.env.ORACLE_KEY_FINGERPRINT,
		region: process.env.ORACLE_REGION || 'us-ashburn-1'
	};
}

// Custom settings - place plugin-specific settings here
var settings = {};

// If running in GovCloud, uncomment the following
// settings.govcloud = true;

// Determine if scan is a compliance scan
var complianceArgs = process.argv
	.filter(function (arg) {
		return arg.startsWith('--compliance=')
	})
	.map(function (arg) {
		return arg.substring(13)
	})
var compliance = complianceControls.create(complianceArgs)
if (!compliance) {
	console.log('ERROR: Unsupported compliance mode. Please use one of the following:');
	console.log('       --compliance=hipaa');
	console.log('       --compliance=pci');
	console.log('       --compliance=cis');
	console.log('       --compliance=cis-1');
	console.log('       --compliance=cis-2');
	process.exit();
}

// Initialize any suppression rules based on the the command line arguments
var suppressionFilter = suppress.create(process.argv)

// Initialize the output handler
var outputHandler = output.create(process.argv)

// The original cloudsploit always has a 0 exit code. With this option, we can have
// the exit code depend on the results (useful for integration with CI systems)
var useStatusExitCode = process.argv.includes('--statusExitCode')

// Configure Service Provider Collectors
var serviceProviders = {
	aws : {
		name: "aws",
		collector: require('./collectors/aws/collector.js'),
		config: AWSConfig,
		apiCalls: [],
		skipRegions: []     // Add any regions you wish to skip here. Ex: 'us-east-2'
	},
	azure : {
		name: "azure",
		collector: require('./collectors/azure/collector.js'),
		config: AzureConfig,
		apiCalls: [],
		skipRegions: []     // Add any locations you wish to skip here. Ex: 'East US'
	},
	github: {
		name: "github",
		collector: require('./collectors/github/collector.js'),
		config: GitHubConfig,
		apiCalls: []
	},
	oracle: {
		name: "oracle",
		collector: require('./collectors/oracle/collector.js'),
		config: OracleConfig,
		apiCalls: []
	}
}

// Ignore Service Providers without a Config Object
for (provider in serviceProviders){
	if (serviceProviders[provider].config == undefined) delete serviceProviders[provider];
}

// STEP 1 - Obtain API calls to make
console.log('INFO: Determining API calls to make...');

function getMapValue(obj, key) {
	if (obj.hasOwnProperty(key))
		return obj[key];
	throw new Error("Invalid map key.");
}

for (p in plugins) {
	for (sp in serviceProviders) {
		var serviceProviderPlugins = getMapValue(plugins, serviceProviders[sp].name);
		var serviceProviderAPICalls = serviceProviders[sp].apiCalls;
		var serviceProviderConfig = serviceProviders[sp].config;
		for (spp in serviceProviderPlugins) {
			var plugin = getMapValue(serviceProviderPlugins, spp);
			// Skip GitHub plugins that do not match the run type
			if (sp == 'github' && serviceProviderConfig.organization &&
				plugin.types.indexOf('org') === -1) continue;

			if (sp == 'github' && !serviceProviderConfig.organization &&
				plugin.types.indexOf('user') === -1) continue;
			
			// Skip if our compliance set says don't run the rule
			if (!compliance.includes(spp, plugin)) continue;

			for (pac in plugin.apis) {
				if (serviceProviderAPICalls.indexOf(plugin.apis[pac]) === -1) {
					serviceProviderAPICalls.push(plugin.apis[pac]);
				}
			}
		}
	}
}

console.log('INFO: API calls determined.');
console.log('INFO: Collecting metadata. This may take several minutes...');

// STEP 2 - Collect API Metadata from Service Providers
async.map(serviceProviders, function (serviceProviderObj, serviceProviderDone) {
	serviceProviderObj.collector(serviceProviderObj.config, {api_calls: serviceProviderObj.apiCalls, skip_regions: serviceProviderObj.skipRegions}, function (err, collection) {
		if (err || !collection) return console.log('ERROR: Unable to obtain API metadata');

		console.log('');
		console.log('-----------------------');
		console.log(serviceProviderObj.name.toUpperCase());
		console.log('-----------------------');
		console.log('');
		console.log('');
		console.log('INFO: Metadata collection complete. Analyzing...');
		console.log('INFO: Analysis complete. Scan report to follow...\n');
		console.log('');

		var serviceProviderPlugins = getMapValue(plugins, serviceProviderObj.name);

		async.mapValuesLimit(serviceProviderPlugins, 10, function (plugin, key, pluginDone) {
			if (!compliance.includes(key, plugin)) {
				return pluginDone(null, 0);
			}

			// Skip GitHub plugins that do not match the run type
			if (serviceProviderObj.name == 'github' &&
				serviceProviderObj.config.organization &&
				plugin.types.indexOf('org') === -1) return pluginDone(null, 0);

			if (serviceProviderObj.name == 'github' &&
				!serviceProviderObj.config.organization &&
				plugin.types.indexOf('user') === -1) return pluginDone(null, 0);

			var maximumStatus = 0
			plugin.run(collection, settings, function(err, results) {
				outputHandler.startCompliance(plugin, key, compliance)

				for (r in results) {
					// If we have suppressed this result, then don't process it
					// so that it doesn't affect the return code.
					if (suppressionFilter([key, results[r].region || 'any', results[r].resource || 'any'].join(':'))) {
						continue;
					}

					// Write out the result (to console or elsewhere)
					outputHandler.writeResult(results[r], plugin, key)

					// Add this to our tracking fo the worst status to calculate
					// the exit code
					maximumStatus = Math.max(maximumStatus, results[r].status)
				}

				outputHandler.endCompliance(plugin, key, compliance)

				setTimeout(function() { pluginDone(err, maximumStatus); }, 0);
			});
		}, function(err, results){
			if (err) return console.log(err);
			var summaryStatus = Math.max(...Object.values(results))
			serviceProviderDone(err, summaryStatus);
		});
	});
}, function (err, results) {
	// console.log(JSON.stringify(collection, null, 2));
	outputHandler.close()
	if (useStatusExitCode) {
		process.exitCode = Math.max(results)
	}
	console.log('Done');
});