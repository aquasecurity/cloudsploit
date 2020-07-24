var async = require('async');
var plugins = require('./exports.js');
var complianceControls = require('./compliance/controls.js');
var suppress = require('./postprocess/suppress.js');
var output = require('./postprocess/output.js');

/**
 * The main function to execute CloudSploit scans.
 * @param AWSConfig The configuration for AWS. If undefined, then don't run.
 * @param AzureConfig The configuration for Azure. If undefined, then don't run.
 * @param GitHubConfig The configuration for Github. If undefined, then don't run.
 * @param OracleConfig The configuration for Oracle. If undefined, then don't run.
 * @param GoogleConfig The configuration for Google. If undefined, then don't run.

 * @param settings General purpose settings.
 */
var engine = function(AWSConfig, AzureConfig, GitHubConfig, OracleConfig, GoogleConfig, settings) {
    // Determine if scan is a compliance scan
    var complianceArgs = process.argv
        .filter(function(arg) {
            return arg.startsWith('--compliance=');
        })
        .map(function(arg) {
            return arg.substring(13);
        });
    var compliance = complianceControls.create(complianceArgs);
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
    var suppressionFilter = suppress.create(process.argv);

    // Initialize the output handler
    var outputHandler = output.create(process.argv);

    // The original cloudsploit always has a 0 exit code. With this option, we can have
    // the exit code depend on the results (useful for integration with CI systems)
    var useStatusExitCode = process.argv.includes('--statusExitCode');

    // Configure Service Provider Collectors
    var serviceProviders = {
        aws : {
            name: 'aws',
            collector: require('./collectors/aws/collector.js'),
            config: AWSConfig,
            apiCalls: [],
            skipRegions: []     // Add any regions you wish to skip here. Ex: 'us-east-2'
        },
        azure : {
            name: 'azure',
            collector: require('./collectors/azure/collector.js'),
            config: AzureConfig,
            apiCalls: [],
            skipRegions: []     // Add any locations you wish to skip here. Ex: 'East US'
        },
        github: {
            name: 'github',
            collector: require('./collectors/github/collector.js'),
            config: GitHubConfig,
            apiCalls: []
        },
        oracle: {
            name: 'oracle',
            collector: require('./collectors/oracle/collector.js'),
            config: OracleConfig,
            apiCalls: []
        },
        google: {
            name: 'google',
            collector: require('./collectors/google/collector.js'),
            config: GoogleConfig,
            apiCalls: []
        }
    };

    // Ignore Service Providers without a Config Object
    for (var provider in serviceProviders){
        if (serviceProviders[provider].config == undefined) delete serviceProviders[provider];
    }

    // STEP 1 - Obtain API calls to make
    console.log('INFO: Determining API calls to make...');

    function getMapValue(obj, key) {
        if (Object.prototype.hasOwnProperty.call(obj, key))
            return obj[key];
        throw new Error('Invalid map key.');
    }

    for (var p in plugins) {
        if (!plugins[p]) continue;
        for (var sp in serviceProviders) {
            var serviceProviderPlugins = getMapValue(plugins, serviceProviders[sp].name);
            var serviceProviderAPICalls = serviceProviders[sp].apiCalls;
            var serviceProviderConfig = serviceProviders[sp].config;
            for (var spp in serviceProviderPlugins) {
                var plugin = getMapValue(serviceProviderPlugins, spp);
                // Skip GitHub plugins that do not match the run type
                if (sp == 'github' && serviceProviderConfig.organization &&
                    plugin.types.indexOf('org') === -1) continue;

                if (sp == 'github' && !serviceProviderConfig.organization &&
                    plugin.types.indexOf('user') === -1) continue;
                
                // Skip if our compliance set says don't run the rule
                if (!compliance.includes(spp, plugin)) continue;

                for (var pac in plugin.apis) {
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
    async.map(serviceProviders, function(serviceProviderObj, serviceProviderDone) {

        settings.api_calls = serviceProviderObj.apiCalls;
        settings.skip_regions = serviceProviderObj.skipRegions;

        serviceProviderObj.collector(serviceProviderObj.config, settings, function(err, collection) {
            if (err || !collection) return console.log(`ERROR: Unable to obtain API metadata: ${err}`);
            outputHandler.writeCollection(collection, serviceProviderObj.name);

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

            async.mapValuesLimit(serviceProviderPlugins, 10, function(plugin, key, pluginDone) {
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

                var maximumStatus = 0;
                plugin.run(collection, settings, function(err, results) {
                    outputHandler.startCompliance(plugin, key, compliance);

                    for (var r in results) {
                        // If we have suppressed this result, then don't process it
                        // so that it doesn't affect the return code.
                        if (suppressionFilter([key, results[r].region || 'any', results[r].resource || 'any'].join(':'))) {
                            continue;
                        }

                        // Write out the result (to console or elsewhere)
                        outputHandler.writeResult(results[r], plugin, key);

                        // Add this to our tracking fo the worst status to calculate
                        // the exit code
                        maximumStatus = Math.max(maximumStatus, results[r].status);
                    }

                    outputHandler.endCompliance(plugin, key, compliance);

                    setTimeout(function() { pluginDone(err, maximumStatus); }, 0);
                });
            }, function(err, results){
                if (err) return console.log(err);
                var summaryStatus = Math.max(...Object.values(results));
                serviceProviderDone(err, summaryStatus);
            });
        });
    }, function(err, results) {
        // console.log(JSON.stringify(collection, null, 2));
        outputHandler.close();
        if (useStatusExitCode) {
            process.exitCode = Math.max(results);
        }
        console.log('Done');
    });
};

module.exports = engine;