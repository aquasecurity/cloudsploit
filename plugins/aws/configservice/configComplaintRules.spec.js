const expect = require('chai').expect;
var configComplaintRules = require('./configComplaintRules');

const describeConfigRules = [
    {
        "ConfigRuleName": "restricted-ssh",
        "ConfigRuleArn": "arn:aws:config:us-east-1:000011112222:config-rule/config-rule-vhwbj2",
        "ConfigRuleId": "config-rule-vhwbj2",
        "Description": "Checks whether security groups that are in use disallow unrestricted incoming SSH traffic.",            "Scope": {
            "ComplianceResourceTypes": [
                "AWS::EC2::SecurityGroup"
            ]
        },
        "Source": {
            "Owner": "AWS",
            "SourceIdentifier": "INCOMING_SSH_DISABLED"
        },
        "InputParameters": "{}",
        "ConfigRuleState": "ACTIVE"
    }
];

const getComplianceDetailsByConfigRule = [
    {
        "EvaluationResults": [
            {
                "EvaluationResultIdentifier": {
                    "EvaluationResultQualifier": {
                        "ConfigRuleName": "restricted-ssh",
                        "ResourceType": "AWS::EC2::SecurityGroup",
                        "ResourceId": "sg-008a9126e4f284b6c"
                    },
                    "OrderingTimestamp": "2022-02-15T15:17:41.028000+05:00"
                },
                "ComplianceType": "COMPLIANT",
                "ResultRecordedTime": "2022-03-10T19:27:49.203000+05:00",
                "ConfigRuleInvokedTime": "2022-03-10T19:27:48.910000+05:00"
            },
        ]
    },   
    {
        "EvaluationResults": []
    }
];

const createCache = (describeConfigRules, getComplianceDetailsByConfigRule, describeConfigRulesErr, getErr) => {
    var ruleName = (describeConfigRules && describeConfigRules.length) ? describeConfigRules[0].ConfigRuleName : null;
    return {
        configservice: {
            describeConfigRules: {
                'us-east-1': {
                    err: describeConfigRulesErr,
                    data: describeConfigRules
                }
            },
            getComplianceDetailsByConfigRule: {
                'us-east-1': {
                    [ruleName]: {
                        err: getErr,
                        data: getComplianceDetailsByConfigRule
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        configservice: {
            describeConfigRules: {
                'us-east-1': null
            }
        }
    };
};

describe('configComplaintRules', function () {
    describe('run', function () {
        it('should PASS if Amazon Config rule returns compliant evaluation results', function (done) {
            const cache = createCache(describeConfigRules, getComplianceDetailsByConfigRule[1]);
            configComplaintRules.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Amazon Config rule returns compliant evaluation results')
                done();
            });
        });

        it('should FAIL if Amazon Config rule returns noncompliant evaluation results', function (done) {
            const cache = createCache(describeConfigRules, getComplianceDetailsByConfigRule[0]);
            configComplaintRules.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Amazon Config rule returns noncompliant evaluation results')
                done();
            });
        });

        it('should PASS if No Config Rules found', function (done) {
            const cache = createCache([]);
            configComplaintRules.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Config Rules found')
                done();
            });
        });

        it('should UNKNOWN if Unable to query Config Rules', function (done) {
            const cache = createCache(describeConfigRules, getComplianceDetailsByConfigRule[0], { message: 'error to query for Config Rules'});
            configComplaintRules.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query Config Rules')
                done();
            });
        });

        it('should not return anything if query Config Rules not found', function (done) {
            const cache = createNullCache();
            configComplaintRules.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
