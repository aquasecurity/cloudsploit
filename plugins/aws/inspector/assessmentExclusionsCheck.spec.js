var expect = require('chai').expect;
var async = require('async');
var helpers = require('../../../helpers/aws');
var inspectorAssessmentExclusionCheck = require('./assessmentExclusionsCheck'); 

const listAssessmentTemplates = [
    "arn:aws:inspector:us-east-1:123456789012:target/0-nvg8Tm4A/template/0-OXqJxJvw",
    "arn:aws:inspector:us-east-1:123456789012:target/0-nvg8Tm4A/template/0-VnJ4HhPd"
];

const listAssessmentRuns = {
    "assessmentRunArns": [
        "arn:aws:inspector:us-east-1:123456789012:target/0-nvg8Tm4A/template/0-OXqJxJvw/run/0-M8S8FW0L",
        "arn:aws:inspector:us-east-1:123456789012:target/0-nvg8Tm4A/template/0-VnJ4HhPd/run/0-x45KIf3j"
    ]
};

const listExclusions = {
    "exclusionArns": [
        "arn:aws:inspector:us-east-1:123456789012:exclusion/0-abcdefg1",
        "arn:aws:inspector:us-east-1:123456789012:exclusion/0-abcdefg2"
    ]
};

const createCache = (assessmentTemplates, assessmentRuns, exclusions) => {
    return {
        inspector: {
            listAssessmentTemplates: {
                'us-east-1': {
                    data: assessmentTemplates
                }
            },
            listAssessmentRuns: {
                'us-east-1': {
                    data: assessmentRuns.assessmentRunArns
                }
            },
            describeAssessmentRuns: {
                'us-east-1': {
                    [assessmentRuns.assessmentRunArns[0]]: {
                        data: {
                            assessmentRuns: [
                                {
                                    completedAt: "2023-08-20T14:30:00Z",
                                    assessmentTemplateArn: assessmentTemplates[0]
                                }
                            ]
                        }
                    },
                    [assessmentRuns.assessmentRunArns[1]]: {
                        data: {
                            assessmentRuns: [
                                {
                                    completedAt: "2023-08-21T14:30:00Z",
                                    assessmentTemplateArn: assessmentTemplates[1]
                                }
                            ]
                        }
                    }
                }
            },
            listExclusions: {
                'us-east-1': {
                    [assessmentRuns.assessmentRunArns[0]]: {
                        data: exclusions
                    },
                    [assessmentRuns.assessmentRunArns[1]]: {
                        data: exclusions
                    }
                }
            }
        }
    };
};

describe('inspectorAssessmentExclusionCheck', function () {
    describe('run', function () {
        it('should PASS if assessment template has no Exclusions', function (done) {
            const cache = createCache(listAssessmentTemplates, listAssessmentRuns, {exclusionArns:[]});
            inspectorAssessmentExclusionCheck.run(cache, {}, (err, results) => {
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Assessment Template has no Exclusions');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if assessment template has Exclusions', function (done) {
            const cache = createCache(listAssessmentTemplates, listAssessmentRuns, listExclusions);
            inspectorAssessmentExclusionCheck.run(cache, {}, (err, results) => {
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Assessment Template has 2 Exclusions');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if there are no assessment templates', function (done) {
            const cache = createCache([], listAssessmentRuns, []);
            inspectorAssessmentExclusionCheck.run(cache, {}, (err, results) => {
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if there are no assessment runs', function (done) {
            const cache = createCache(listAssessmentTemplates, { assessmentRunArns: [] }, []);
            inspectorAssessmentExclusionCheck.run(cache, {}, (err, results) => {
                expect(results[0].status).to.equal(0);
                done();
            });
        });
    });
});
