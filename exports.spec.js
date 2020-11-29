var expect = require('chai').expect;
var tests = require('./exports');

// This function is used to ensure function arguments
// are configured correctly for each plugin
var STRIP_COMMENTS = /((\/\/.*$)|(\/\*[\s\S]*?\*\/))/mg;
var ARGUMENT_NAMES = /([^\s,]+)/g;
function getParamNames(func) {
    var fnStr = func.toString().replace(STRIP_COMMENTS, '');
    var result = fnStr.slice(fnStr.indexOf('(')+1, fnStr.indexOf(')')).match(ARGUMENT_NAMES);
    if (result === null) result = [];
    return result;
}

describe('exports', function () {
    it('should use the proper format for each test', function () {
        for (var cloud in tests) {
            for (var test in tests[cloud]) {
                var lTest = tests[cloud][test];

                // Check test properties
                expect(lTest, `Test: ${test} is not an object`).to.be.an('object');
                ['title', 'category', 'description', 'more_info',
                 'recommended_action', 'link', 'apis'].forEach(function(prop){
                    expect(lTest, `Test: ${test} does not have property: ${prop}`).to.have.property(prop);
                });

                // Check settings properties, if they exist
                if (lTest.settings) {
                    expect(lTest.settings).to.be.an('object');
                    Object.values(lTest.settings).forEach(function(setting){
                        expect(setting).to.be.an('object');
                        ['name', 'description', 'regex', 'default'].forEach(function(prop){
                            expect(setting, `Test: ${test} does not have settings property: ${prop}`).to.have.property(prop);
                        });
                    });
                }

                // Check run function and arguments
                expect(lTest.run, `Test: ${test} run is not a function`).to.be.an('function');
                var runParams = getParamNames(lTest.run);
                expect(runParams[0], `Test: ${test} run function parameter 1 is not: cache`).to.equal('cache');
                expect(runParams[1], `Test: ${test} run function parameter 2 is not: settings`).to.equal('settings');
                expect(runParams[2], `Test: ${test} run function parameter 3 is not: callback`).to.equal('callback');

                // Check remediate function and arguments
                if (lTest.remediate) {
                    expect(lTest.remediate, `Test: ${test} remediate is not a function`).to.be.an('function');
                    var remediateParams = getParamNames(lTest.remediate);
                    expect(remediateParams[0], `Test: ${test} remediate function parameter 1 is not: config`).to.equal('config');
                    expect(remediateParams[1], `Test: ${test} remediate function parameter 2 is not: cache`).to.equal('cache');
                    expect(remediateParams[2], `Test: ${test} remediate function parameter 3 is not: settings`).to.equal('settings');
                    expect(remediateParams[3], `Test: ${test} remediate function parameter 4 is not: resource`).to.equal('resource');
                    expect(remediateParams[4], `Test: ${test} remediate function parameter 4 is not: callback`).to.equal('callback');

                    // Check remediation properties, if they exist
                    expect(lTest.apis_remediate).to.be.an('array');
                    lTest.apis_remediate.forEach(function(apiCall){
                        expect(apiCall, `Test: ${test} API call in apis_remediate is not a string`).to.be.an('string');
                    });

                    expect(lTest.actions, `Test: ${test} actions is not an object`).to.be.an('object');
                    expect(lTest.actions.remediate, `Test: ${test} actions.remediate is not an array`).to.be.an('array');
                    expect(lTest.actions.rollback, `Test: ${test} actions.rollback is not an array`).to.be.an('array');
                    
                    lTest.actions.remediate.forEach(function(apiCall){
                        expect(apiCall, `Test: ${test} actions.remediate call is not a string`).to.be.an('string');
                    });

                    lTest.actions.rollback.forEach(function(apiCall){
                        expect(apiCall, `Test: ${test} actions.rollback call is not a string`).to.be.an('string');
                    });

                    expect(lTest.permissions, `Test: ${test} permissions is not an object`).to.be.an('object');
                    expect(lTest.permissions.remediate, `Test: ${test} permissions.remediate is not an array`).to.be.an('array');
                    expect(lTest.permissions.rollback, `Test: ${test} permissions.rollback is not an array`).to.be.an('array');
                    
                    lTest.permissions.remediate.forEach(function(apiCall){
                        expect(apiCall, `Test: ${test} permissions.remediate call is not a string`).to.be.an('string');
                    });

                    lTest.permissions.rollback.forEach(function(apiCall){
                        expect(apiCall, `Test: ${test} actions.rollback call is not a string`).to.be.an('string');
                    });

                    expect(lTest.remediation_description, `Test: ${test} remediation_description parameter is not a string`).to.be.an('string');

                    if (lTest.realtime_triggers) {
                        expect(lTest.realtime_triggers, `Test: ${test} realtime_triggers parameter is not an array`).to.be.an('array');
                        lTest.realtime_triggers.forEach(function(lTrigger){
                            expect(lTrigger, `Test: ${test} realtime_triggers property is not a string`).to.be.an('string');
                        });
                    }

                    expect(lTest.remediation_min_version, `Test: ${test} remediation_min_version parameter is not a string`).to.be.a('string');
                    expect(lTest.remediation_min_version.length, `Test: ${test} remediation_min_version parameter  length is not 12`).to.equal(12);

                    if (lTest.remediation_inputs) {
                        expect(lTest.remediation_inputs, `Test: ${test} remediation_inputs is not an object`).to.be.an('object');
                        Object.keys(lTest.remediation_inputs).forEach(function(rInput){
                            expect(lTest.remediation_inputs[rInput].name, `Test: ${test} remediation_inputs.${rInput}.name is not a string`).to.be.a('string');
                            expect(lTest.remediation_inputs[rInput].description, `Test: ${test} remediation_inputs.${rInput}.description is not a string`).to.be.a('string');
                            expect(lTest.remediation_inputs[rInput].regex, `Test: ${test} remediation_inputs.${rInput}.regex is not a string`).to.be.a('string');
                        });
                    }
                }

                if (lTest.rollback) {
                    expect(lTest.rollback, `Test: ${test} rollback is not a function`).to.be.an('function');
                    var rollbackParams = getParamNames(lTest.rollback);
                    expect(rollbackParams[0], `Test: ${test} rollback function parameter 1 is not: config`).to.equal('config');
                    expect(rollbackParams[1], `Test: ${test} rollback function parameter 2 is not: cache`).to.equal('cache');
                    expect(rollbackParams[2], `Test: ${test} rollback function parameter 3 is not: settings`).to.equal('settings');
                    expect(rollbackParams[3], `Test: ${test} rollback function parameter 4 is not: resource`).to.equal('resource');
                    expect(rollbackParams[4], `Test: ${test} rollback function parameter 4 is not: callback`).to.equal('callback');
                }
            }
        }
    });
});
