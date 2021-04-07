// Executes the policy
var opahelpers = require('./opaInstaller');
var helpers = require('../aws');
var async = require('async');

// data: path for the rego file. we can later improve it to have multiple data files or bundle which will include
//      data and input togather
// input: input in a json format.
var opaEval = (data, input, opaPath, rules, messages,callback) => {
    var results ={};

    async.eachOf(rules, function(rule, ruleName, cb) {
        var command = `${opaPath} eval -i ${input} -d ${data} "${rule}"`;
        opahelpers.executeCommand(command, {shell: true}, (err, stdoutbuf) => {
            if (err) {
                return cb(err);
            }
            var result = JSON.parse(stdoutbuf);
            results[ruleName] = result.result[0].expressions[0].value;
            cb();
        });
    }, function(err) {
        if (err) {
            console.log(err);
            return callback(err);
        }
        var finalresults = [];
        for ( var res in results ){
            var caseResult = results[res];
            caseResult.forEach(resultItem => {
                var resource = resultItem.arn;
                var region = resultItem.region;
                var newMassage = resultItem.msg;
                var status = resultItem.status;
                helpers.addResult(finalresults, parseInt(status),
                    newMassage,
                    region, resource);
            });
        }
        return callback(null, finalresults);
    });
};

module.exports = {
    opaEval: opaEval
};
// ./opa eval -i input.json -d example.rego "data.example.violation[x]"