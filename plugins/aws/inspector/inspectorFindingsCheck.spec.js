var expect = require('chai').expect;
var async = require('async');
var helpers = require('../../../helpers/aws');
var inspectorFindingsCheck = require('./inspectorFindingsCheck'); 

const listFindings = [
    "arn:aws:inspector:us-east-1:123456789012:finding/0-abcdefg1",
    "arn:aws:inspector:us-east-1:123456789012:finding/0-abcdefg2"
];

const listAssessmentRuns = {
    "assessmentRunArns": [
        "arn:aws:inspector:us-east-1:123456789012:target/0-nvg8Tm4A/template/0-OXqJxJvw/run/0-M8S8FW0L",
        "arn:aws:inspector:us-east-1:123456789012:target/0-nvg8Tm4A/template/0-VnJ4HhPd/run/0-x45KIf3j"
    ]
};

const listAssessmentTemplates = [
    "arn:aws:inspector:us-east-1:123456789012:target/0-nvg8Tm4A/template/0-OXqJxJvw",
    "arn:aws:inspector:us-east-1:123456789012:target/0-nvg8Tm4A/template/0-VnJ4HhPd"
];

const createCache = (findings, assessmentRuns, assessmentTemplates) => {
    return {
        inspector: {
            listFindings: {
                'us-east-1': {
                    data: findings
                }
            },
            listAssessmentRuns: {
                'us-east-1': {
                    data: assessmentRuns.assessmentRunArns
                }
            },
            listAssessmentTemplates: {
                'us-east-1': {
                    data: assessmentTemplates
                }
            },
            describeFindings: {
                'us-east-1': {
                    [findings[0]]: {
                        data: {
                            findings: [
                                {
                                    serviceAttributes: {
                                        assessmentRunArn: assessmentRuns.assessmentRunArns[0]
                                    }
                                }
                            ]
                        }
                    },
                    [findings[1]]: {
                        data: {
                            findings: [
                                {
                                    serviceAttributes: {
                                        assessmentRunArn: assessmentRuns.assessmentRunArns[1]
                                    }
                                }
                            ]
                        }
                    }
                }
            },
            describeAssessmentRuns: {
                'us-east-1': {
                    [assessmentRuns.assessmentRunArns[0]]: {
                        data: {
                            assessmentRuns: [
                                {
                                    arn: assessmentRuns.assessmentRunArns[0],
                                    assessmentTemplateArn: assessmentTemplates[0]

                                }
                            ]
                        }
                    },
                    [assessmentRuns.assessmentRunArns[1]]: {
                        data: {
                            assessmentRuns: [
                                {
                                    arn: assessmentRuns.assessmentRunArns[1],
                                    assessmentTemplateArn: assessmentTemplates[0]

                                }
                            ]
                        }
                    }
                }
            }
        }
    };
};

describe('inspectorFindingsCheck', function () {
    describe('run', function () {
        it('should PASS if assessment template has no Findings', function (done) {
            const cache = createCache([], listAssessmentRuns, listAssessmentTemplates);
            inspectorFindingsCheck.run(cache, {}, (err, results) => {
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Inspector Findings found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if assessment template has Findings', function (done) {
            const cache = createCache(listFindings, listAssessmentRuns, listAssessmentTemplates);
            inspectorFindingsCheck.run(cache, {}, (err, results) => {
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Assessment Template has 2 Findings');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if there are no assessment templates', function (done) {
            const cache = createCache([], { assessmentRunArns: [] }, []);
            inspectorFindingsCheck.run(cache, {}, (err, results) => {
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if there are no assessment runs', function (done) {
            const cache = createCache(listFindings, { assessmentRunArns: [] }, listAssessmentTemplates);
            inspectorFindingsCheck.run(cache, {}, (err, results) => {
                expect(results[0].status).to.equal(0);
                done();
            });
        });
    });
});
