var async = require('async');
var plugins = require('./exports.js');
var cache = {};
var benchmarkTest = (process.argv.indexOf('--cis-benchmarks') > -1);
var benchmarkList = ['1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '1.8', '1.9', '1.10', '1.11', '1.12', '1.13', '1.15',
                     '2.1', '2.2', '2.3', '2.4', '2.5', '2.6', '2.7', '2.8',
                     '4.1', '4.2', '4.3', '4.4'];
var benchmarkMap = {};

// OPTION 1: Configure AWS credentials through hard-coded key and secret
// var AWSConfig = {
//     accessKeyId: '',
//     secretAccessKey: '',
//     sessionToken: '',
//     region: 'us-east-1'
// };

// OPTION 2: Import an AWS config file containing credentials
// var AWSConfig = require(__dirname + '/credentials.json');

// OPTION 3: Set AWS credentials in environment variables

if (benchmarkTest) {
    console.log('Running CIS benchmark tests. This may take a few minutes...\nFor more details on the results, run the scan again without the --cis-benchmarks argument.');
} else {
    console.log('CATEGORY\tPLUGIN\t\t\t\tRESOURCE\t\t\tREGION\t\tSTATUS\tMESSAGE');
}

async.forEachOfLimit(plugins, 10, function(plugin, key, callback){
    if (benchmarkTest && !plugin.cis_benchmark) return callback();

    plugin.run(AWSConfig, cache, function(err, results){
        var benchmarkStatus = 'PASS';
        for (r in results) {
            var statusWord;
            if (results[r].status === 0) {
                statusWord = 'OK';
            } else if (results[r].status === 1) {
                statusWord = 'WARN';
                if (benchmarkStatus !== 'UNKN') benchmarkStatus = 'FAIL';
            } else if (results[r].status === 2) {
                statusWord = 'FAIL';
                if (benchmarkStatus !== 'UNKN') benchmarkStatus = 'FAIL';
            } else {
                statusWord = 'UNKNOWN';
                benchmarkStatus = 'UNKN';
            }
            if (!benchmarkTest) {
                console.log(plugin.category + '\t' + plugin.title + '\t' + (results[r].resource || 'N/A') + '\t' + (results[r].region || 'Global') + '\t\t' + statusWord + '\t' + results[r].message);
            }
        }

        if (benchmarkTest) {
            var benchmarkNumber = (plugin.cis_benchmark.length == 3) ? plugin.cis_benchmark + ' ' : plugin.cis_benchmark;
            benchmarkMap[benchmarkList.indexOf(plugin.cis_benchmark)] = benchmarkNumber + ' ' + benchmarkStatus + ' ' + plugin.title;
        }

        callback(err);
    });
}, function(err, data){
    if (err) return console.log(err);
    if (benchmarkTest) {
        for (b in benchmarkMap) {
            console.log(benchmarkMap[b]);
        }
    }
});
