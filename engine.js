var async = require('async');
var exports = require('./exports.js');
var suppress = require('./postprocess/suppress.js');
var output = require('./postprocess/output.js');
var azureHelper = require('./helpers/azure/auth.js');

function runAuth(settings, remediateConfig, callback) {
    if (settings.cloud && settings.cloud == 'azure') {
        azureHelper.login(remediateConfig, function(err, loginData) {
            if (err) return callback(err);
            remediateConfig.token = loginData.token;
            return callback();
        });
    } else callback();
}

async function uploadResultsToBlob(resultsObject, storageConnection, blobContainerName) {
    var azureStorage = require('@azure/storage-blob');
    try {
        const blobServiceClient = azureStorage.BlobServiceClient.fromConnectionString(storageConnection);
        const containerClient = blobServiceClient.getContainerClient(blobContainerName);
        const exists = await containerClient.exists();
        if (!exists) await containerClient.create();
        const blobName = `results-${Date.now()}.json`;
        const blockBlobClient = containerClient.getBlockBlobClient(blobName);
        const data = JSON.stringify(resultsObject, null, 2);
        await blockBlobClient.upload(data, data.length);
    } catch (error) {
        console.log(`Failed to upload results to blob: ${error.message}`);
    }
}

var engine = function(cloudConfig, settings) {
    var suppressionFilter = suppress.create(settings.suppress);
    var outputHandler = output.create(settings);
    var collector = require(`./collectors/${settings.cloud}/collector.js`);
    var plugins = exports[settings.cloud];

    var resourceMap;
    try {
        resourceMap = require(`./helpers/${settings.cloud}/resources.js`);
    } catch (e) {
        resourceMap = {};
    }

    if (settings.skip_paginate) console.log('INFO: Skipping AWS pagination mode');

    console.log('INFO: Determining API calls to make...');
    console.log('DEBUG: Plugins for', settings.cloud, ':', plugins);

    if (!plugins || Object.keys(plugins).length === 0) {
        console.error(`ERROR: No plugins found for cloud provider: ${settings.cloud}`);
        process.exit(1);
    }

    var skippedPlugins = [];
    var apiCalls = [];

    Object.entries(plugins).forEach(function(p) {
        var pluginId = p[0];
        var plugin = p[1];
        var skip = false;
        if (settings.plugin && settings.plugin !== pluginId) skip = true;

        if (!skip) {
            if (plugin.apis && Array.isArray(plugin.apis)) {
                plugin.apis.forEach(function(api) {
                    if (apiCalls.indexOf(api) === -1) apiCalls.push(api);
                });
            } else {
                console.warn(`WARNING: Plugin ${plugin.title || pluginId} has no valid 'apis' property`);
            }
        }
    });

    if (!apiCalls.length) return console.log('ERROR: Nothing to collect.');

    // Define API-to-collector mapping
    const apiToCollectorMap = {
        'ListServersDetails': 'ecs', // Map ListServersDetails to the ecs collector
        'ListVpcs': 'vpcs',
        'ListBuckets': 'obs',
        //'ListUsers': 'iam'
        // Add more mappings as needed for other APIs
    };

    // Determine which collectors to run based on API calls
    let collectorsToRun = [];
    apiCalls.forEach(api => {
        if (apiToCollectorMap[api] && !collectorsToRun.includes(apiToCollectorMap[api])) {
            collectorsToRun.push(apiToCollectorMap[api]);
        }
    });

    console.log(`INFO: Found ${apiCalls.length} API calls to make for ${settings.cloud} plugins`);
    console.log('INFO: Collectors to run:', collectorsToRun);
    console.log('INFO: Collecting metadata. This may take several minutes...');

    collector(cloudConfig, { api_calls: apiCalls }, function(err, collection) {
        if (err || !collection || !Object.keys(collection).length) return console.log(`ERROR: Unable to obtain API metadata: ${err || 'No data returned'}`);

        // Merge pre-collected data (e.g., ECS data from index.js) into the collection
        if (settings.preCollectedData) {
            console.log('DEBUG: Merging pre-collected data into collection:', JSON.stringify(settings.preCollectedData, null, 2));
            collection = { ...collection, ...settings.preCollectedData };
        }

        outputHandler.writeCollection(collection, settings.cloud);

        console.log('INFO: Metadata collection complete. Analyzing...');
        console.log('INFO: Analysis complete. Scan report to follow...');

        var maximumStatus = 0;
        var resultsObject = {};

        async.mapValuesLimit(plugins, 10, function(plugin, key, pluginDone) {
            var postRun = function(err, results) {
                if (err) return console.log(`ERROR: ${err}`);
                if (!results || !results.length) {
                    console.log(`Plugin ${plugin.title} returned no results.`);
                } else {
                    if (!resultsObject[plugin.title]) resultsObject[plugin.title] = [];
                    for (var r in results) {
                        if (suppressionFilter([key, results[r].region || 'any', results[r].resource || 'any'].join(':'))) continue;
                        resultsObject[plugin.title].push(results[r]);
                        outputHandler.writeResult(results[r], plugin, key, null);
                        maximumStatus = Math.max(maximumStatus, results[r].status);
                    }
                }
                pluginDone(err, maximumStatus);
            };
            plugin.check ? plugin.check(collection, postRun) : plugin.run(collection, settings, postRun);
        }, function(err) {
            if (err) return console.log(err);
            if (cloudConfig.StorageConnection && cloudConfig.BlobContainer) uploadResultsToBlob(resultsObject, cloudConfig.StorageConnection, cloudConfig.BlobContainer);
            outputHandler.close();
            console.log('INFO: Scan complete');
        });
    });
};

module.exports = engine;
