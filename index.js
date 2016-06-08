var async = require('async');
var plugins = require('./exports.js');
var cache = {};
var securityReport = (process.argv.indexOf('--security-report') > -1);

var benchmarkMap = {};
var categoryMap = {};

// OPTION 1: Configure AWS credentials through hard-coded key and secret
// var AWSConfig = {
//     accessKeyId: '',
//     secretAccessKey: '',
//     sessionToken: '',
//     region: 'us-east-1'
// };

// OPTION 2: Import an AWS config file containing credentials
// var AWSConfig = require(__dirname + '/credentials.json');
var AWSConfig = require(__dirname + '/../../../cloudsploit-secure/scan-self.json');

// OPTION 3: Set AWS credentials in environment variables

if (securityReport) {
    console.log('Running security report. This may take a few minutes...\nFor more details on the results, run the scan again without the --security-report argument.');
} else {
    console.log('CATEGORY\tPLUGIN\t\t\t\tRESOURCE\t\t\tREGION\t\tSTATUS\tMESSAGE');
}

async.forEachOfLimit(plugins, 10, function(plugin, key, callback){
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
