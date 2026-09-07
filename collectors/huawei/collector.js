'use strict';

const async = require('async');

// Define API-to-collector mapping (same as in engine.js)
const apiToCollectorMap = {
    'ListServersDetails': 'ecs',
    'ListVpcs': 'vpcs',
    'ListBuckets': 'obs',
    'ListUsers': 'iam'
};

module.exports = function(cloudConfig, options, callback) {
    const apiCalls = options.api_calls || [];
    const collection = {};

    // Determine which collectors to run based on API calls
    const collectorsToRun = [];
    apiCalls.forEach(api => {
        if (apiToCollectorMap[api] && !collectorsToRun.includes(apiToCollectorMap[api])) {
            collectorsToRun.push(apiToCollectorMap[api]);
        }
    });

    //console.log('DEBUG: Collectors to run in collector.js:', collectorsToRun);

    if (!collectorsToRun.length) {
        //console.log('INFO: No collectors to run for the given API calls.');
        return callback(null, collection);
    }

    // Load and run each collector
    async.eachSeries(collectorsToRun, (collectorName, done) => {
        //console.log(`DEBUG: Running collector: ${collectorName}`);
        let collector;
        try {
            collector = require(`./${collectorName}`);
        } catch (e) {
            console.error(`ERROR: Could not load collector ${collectorName}: ${e.message}`);
            return done(e);
        }

        collector(cloudConfig, (err, data) => {
            if (err) {
                console.error(`ERROR: Collector ${collectorName} failed: ${err.message}`);
                return done(err);
            }
            collection[collectorName] = data;
            done();
        });
    }, (err) => {
        if (err) return callback(err);
        callback(null, collection);
    });
};
