var fs = require('fs');
var async = require('async');
var plugins = require('./exports.js');
var collector = require('./collect.js');
var cache = {};
var securityReport = (process.argv.indexOf('--security-report') > -1);
var sourceFile = process.argv[process.argv.indexOf('--source') + 1];

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
if (!sourceFile) {
    return console.log('ERROR: Please provide a source file via --source /path/to file');
}

fs.readFile(sourceFile, 'utf8', function(sourceErr, cache){
    if (sourceErr || !cache) {
        return console.log('ERROR: Unable to read source file: ' + (sourceErr || 'No data'));
    }

    try {
        cache = JSON.parse(cache);
    } catch(e) {
        return console.log('ERROR: File is not valid JSON: ' + e);
    }
    

    var categoryMap = {};

    if (securityReport) {
        console.log('Running security report. This may take a few minutes...\nFor more details on the results, run the scan again without the --security-report argument.');
    } else {
        console.log('CATEGORY\tPLUGIN\t\t\t\tRESOURCE\t\t\tREGION\t\tSTATUS\tMESSAGE');
    }

    async.forEachOfLimit(plugins, 10, function(plugin, key, callback){
        plugin.run(cache, function(err, results){
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
                if (!securityReport) {
                    console.log(plugin.category + '\t' + plugin.title + '\t' + (results[r].resource || 'N/A') + '\t' + (results[r].region || 'Global') + '\t\t' + statusWord + '\t' + results[r].message);
                }
            }

            if (securityReport) {
                if (!categoryMap[plugin.category]) categoryMap[plugin.category] = {};
                categoryMap[plugin.category][plugin.title] = benchmarkStatus;
            }

            callback(err);
        });
    }, function(err, data){
        if (err) return console.log(err);
        if (securityReport) {
            for (c in categoryMap) {
                console.log('\n' + c);

                for (p in categoryMap[c]) {
                    console.log('     ' + categoryMap[c][p] + ' ' + p);
                }
            }
        }
    });
});