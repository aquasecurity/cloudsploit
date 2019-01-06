var async = require('async');
var plugins = require('./exports.js');

var AWSConfig;
var AzureConfig;

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

// OPTION 2: Import a service provider config file containing credentials
// AWSConfig = require(__dirname + '/aws_credentials.json');
// AzureConfig = require(__dirname + '/azure_credentials.json');

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
		region: process.env.AZURE_LOCATION || 'East US'
	};
}

// Custom settings - place plugin-specific settings here
var settings = {};

// If running in GovCloud, uncomment the following
// settings.govcloud = true;

// Determine if scan is a compliance scan
var COMPLIANCE;

if (process.argv.join(' ').indexOf('--compliance') > -1) {
    if (process.argv.join(' ').indexOf('--compliance=hipaa') > -1) {
        COMPLIANCE='hipaa';
        console.log('INFO: Compliance mode: HIPAA');
    } else if (process.argv.join(' ').indexOf('--compliance=pci') > -1) {
        COMPLIANCE='pci';
        console.log('INFO: Compliance mode: PCI');
    } else {
        console.log('ERROR: Unsupported compliance mode. Please use one of the following:');
        console.log('       --compliance=hipaa');
        console.log('       --compliance=pci');
        process.exit(1);
    }
}

// Configure Service Provider Collectors
var serviceProviders;
var PROVIDER;

var awsProvider = {
	aws : {
		name: "aws",
		collector: require('./collectors/aws/collector.js'),
		config: AWSConfig,
		apiCalls: [],
		skipRegions: []     // Add any regions you wish to skip here. Ex: 'us-east-2'
	}
    }

var azureProvider = {
	azure : {
		name: "azure",
		collector: require('./collectors/azure/collector.js'),
		config: AzureConfig,
		apiCalls: [],
		skipRegions: []     // Add any locations you wish to skip here. Ex: 'East US'
	}
}

if (process.argv.join(' ').indexOf('--provider') > -1) {
    if (process.argv.join(' ').indexOf('--provider=aws') > -1) {
        if (!AWSConfig || !AWSConfig.accessKeyId) {
            return console.log('ERROR: Invalid AWSConfig');
        }
		PROVIDER='aws';
        console.log('INFO: Provider: AWS');
    } else if (process.argv.join(' ').indexOf('--provider=azure') > -1) {
		if (!AzureConfig || !AzureConfig.ApplicationID) {
			return console.log('ERROR: Invalid AzureConfig');
		}	
        PROVIDER='azure';
        console.log('INFO: Provider: Azure');
    }
} else {
        console.log('ERROR: Unsupported provider. Please use one of the following:');
        console.log('       --provider=aws');
        console.log('       --provider=azure');
        process.exit(1);
}


if (PROVIDER == 'aws') {
	serviceProviders = awsProvider
} else if (PROVIDER == 'azure') {
	serviceProviders = azureProvider
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
		for (spp in serviceProviderPlugins) {
			var plugin = getMapValue(serviceProviderPlugins, spp);
			for (pac in plugin.apis) {
				if (serviceProviderAPICalls.indexOf(plugin.apis[pac]) === -1) {
					if (COMPLIANCE) {
						if (plugin.compliance && plugin.compliance[COMPLIANCE]) {
							serviceProviderAPICalls.push(plugin.apis[pac])
						}
					} else {
						serviceProviderAPICalls.push(plugin.apis[pac]);
					}
				}
			}
		}
	}
}

console.log('INFO: API calls determined.');
console.log('INFO: Collecting metadata. This may take several minutes...');

// STEP 2 - Collect API Metadata from Service Providers
async.eachOf(serviceProviders, function (serviceProviderObj, serviceProviderCb) {
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

		async.forEachOfLimit(serviceProviderPlugins, 10, function (plugin, key, callback) {
			if (COMPLIANCE && (!plugin.compliance || !plugin.compliance[COMPLIANCE])) {
				return callback();
			}

			plugin.run(collection, settings, function(err, results){
				if (COMPLIANCE) {
					console.log('');
					console.log('-----------------------');
					console.log(plugin.title);
					console.log('-----------------------');
					console.log(plugin.compliance[COMPLIANCE]);
					console.log('');
				}
				for (r in results) {
					var statusWord;
					if (results[r].status === 0) {
						statusWord = 'OK';
					} else if (results[r].status === 1) {
						statusWord = 'WARN';
					} else if (results[r].status === 2) {
						statusWord = 'FAIL';
					} else {
						statusWord = 'UNKNOWN';
					}

					console.log(plugin.category + '\t' + plugin.title + '\t' +
						(results[r].resource || 'N/A') + '\t' +
						(results[r].region || 'Global') + '\t\t' +
						statusWord + '\t' + results[r].message);
				}

				setTimeout(function() { callback(err); }, 0);
			});
		}, function(err){
			if (err) return console.log(err);
		});
	});

}, function () {
	//console.log(JSON.stringify(collection, null, 2));
	callback(null, collection);
});
